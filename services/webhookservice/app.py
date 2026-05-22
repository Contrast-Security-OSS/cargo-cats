from flask import Flask, request, jsonify
import os
import requests
import subprocess
import threading
import time
import mysql.connector
from mysql.connector import Error
import sys
import logging

# Configure environment variables with defaults
DB_HOST = os.getenv('DB_HOST', 'cargocats-db')
DB_PORT = os.getenv('DB_PORT', '3306')
DB_NAME = os.getenv('DB_NAME', 'db')
DB_USER = os.getenv('DB_USER', 'cargocats')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'cargocats')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('webhook-service')

app = Flask(__name__)

# Log application startup info
logger.info("---- Webhook Service starting up ----")
logger.info(f"Python version: {sys.version}")

# Try to get Flask version safely
try:
    flask_version = Flask.__version__
except AttributeError:
    try:
        import flask
        flask_version = flask.__version__
    except (AttributeError, ImportError):
        flask_version = "Unknown"

logger.info(f"Flask version: {flask_version}")
logger.info(f"Database configuration: {DB_HOST}:{DB_PORT}/{DB_NAME}")

# Set Flask logger to use our configuration
app.logger.handlers = []
for handler in logging.getLogger().handlers:
    app.logger.addHandler(handler)

def connect_to_db(max_retries=5, retry_delay=10):
    """Connect to database with retry mechanism"""
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            # Database connection parameters
            # Use the global variables instead of environment lookups
            host = DB_HOST
            port = DB_PORT
            database = DB_NAME
            user = DB_USER
            password = DB_PASSWORD
            
            logger.info(f"Attempting database connection to {host}:{port}/{database} (attempt {retry_count+1}/{max_retries})")
            
            connection = mysql.connector.connect(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
                connection_timeout=30  # Increase timeout for connection
            )
            
            if connection.is_connected():
                logger.info("Database connection successful")
                return connection
                
        except Error as e:
            logger.error(f"Database connection failed: {e}")
            retry_count += 1
            
            if retry_count < max_retries:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts")
                raise
                
        except Exception as e:
            logger.error(f"Unexpected error during database connection: {e}")
            retry_count += 1
            
            if retry_count < max_retries:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts")
                raise
    
    return None

def periodic_task():
    """Function that runs every 5 minutes to check for unnotified shipments"""
    logger.info("Periodic task executed")
    
    connection = None
    try:
        # Connect to database with retry mechanism
        connection = connect_to_db()
        
        if connection.is_connected():
            cursor = connection.cursor(dictionary=True)
            
            # Query for shipments that have notification_url and notified = false
            query = """
                SELECT id, tracking_id, status, notification_url, notified 
                FROM shipment 
                WHERE notification_url IS NOT NULL 
                AND notification_url != '' 
                AND notified = FALSE
            """
            
            cursor.execute(query)
            unnotified_shipments = cursor.fetchall()
            
            unnotified_count = len(unnotified_shipments)
            processed_count = 0
            
            logger.info(f"Found {unnotified_count} unnotified shipments")
            
            for shipment in unnotified_shipments:
                shipment_id = shipment['id']
                tracking_id = shipment['tracking_id']
                status = shipment['status']
                notification_url = shipment['notification_url']
                
                logger.info(f"Processing shipment: {tracking_id} (ID: {shipment_id}) - URL: {notification_url}")
                
                try:
                    # Send notification to the URL
                    notification_data = {
                        'shipment_id': shipment_id,
                        'tracking_id': tracking_id,
                        'status': status,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    # Send POST request to the notification URL
                    notification_response = requests.post(
                        notification_url, 
                        json=notification_data, 
                        timeout=10
                    )
                    
                    if notification_response.status_code in [200, 201, 202]:
                        # Update shipment to mark as notified
                        update_query = "UPDATE shipment SET notified = TRUE WHERE id = %s"
                        cursor.execute(update_query, (shipment_id,))
                        connection.commit()
                        
                        processed_count += 1
                        logger.info(f"Successfully notified and updated shipment {tracking_id}")
                    else:
                        logger.warning(f"Notification failed for {tracking_id}: HTTP {notification_response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error sending notification for shipment {tracking_id}: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error processing shipment {tracking_id}: {str(e)}")
            
            cursor.close()
            logger.info(f"Notification check complete: {unnotified_count} unnotified shipments found, {processed_count} successfully processed")
            
    except Error as e:
        logger.error(f"Database error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in periodic task: {str(e)}")
    finally:
        if connection and connection.is_connected():
            connection.close()

def start_background_scheduler(initial_delay=60):
    """Start the background scheduler for periodic tasks"""
    def run_scheduler():
        # Add initial delay to give database time to initialize
        logger.info(f"Scheduler sleeping for {initial_delay} seconds before first periodic task")
        time.sleep(initial_delay)
        
        while True:
            try:
                periodic_task()
            except Exception as e:
                logger.error(f"Error in periodic task: {e}")
                # Continue running even if there's an error
            
            logger.info(f"Next periodic task in 300 seconds")
            time.sleep(300)  # 300 seconds = 5 minutes
    
    # Start the scheduler in a daemon thread so it stops when the main app stops
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info("Background scheduler started - periodic task will run every 5 minutes after initial delay")

@app.route('/')
def home():
    logger.info("Root endpoint accessed")
    return jsonify({"message": "Flask Webhook API is running!"})

@app.route('/webhookNotify', methods=['POST'])
def webhook_notify():
    logger.info("Received webhook notification request")
    
    # Get the URL and method from POST data (JSON or form data)
    if request.is_json:
        data = request.get_json()
        url = data.get('url') if data else None
        method = data.get('method', 'GET').upper() if data else 'GET'
        logger.info(f"JSON request received with URL: {url}, Method: {method}")
    else:
        url = request.form.get('url')
        method = request.form.get('method', 'GET').upper()
        logger.info(f"Form request received with URL: {url}, Method: {method}")
    
    if not url:
        logger.error("Error: URL parameter is missing")
        return jsonify({"error": "URL parameter is required"}), 400
    
    # Validate method parameter
    if method not in ['GET', 'POST']:
        logger.error(f"Error: Invalid method {method} - must be GET or POST")
        return jsonify({"error": "Method must be either 'GET' or 'POST'"}), 400
    
    try:
        logger.info(f"Sending {method} request to {url}")
        
        # Make the request based on the specified method
        if method == 'POST':
            response = requests.post(url, timeout=10)
        else:  # GET
            response = requests.get(url, timeout=10)
        
        logger.info(f"Request completed with status code: {response.status_code}")
        if len(response.text) > 200:
            logger.info(f"Response content: {response.text[:200]}...")
        else:
            logger.info(f"Response content: {response.text}")
            
        return jsonify({
            "message": f"Webhook notification sent successfully using {method}",
            "method_used": method,
            "status_code": response.status_code,
            "response": response.text  # Show entire response
        })
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send webhook notification: {str(e)}")
        return jsonify({"error": f"Failed to send webhook notification: {str(e)}"}), 500

@app.route('/testConnection', methods=['POST'])
def test_connection():   
    logger.info("Received test connection request")
    
    if request.is_json:
        data = request.get_json()
        url = data.get('url') if data else None
        logger.info(f"JSON request received with URL: {url}")
    else:
        url = request.form.get('url')
        logger.info(f"Form request received with URL: {url}")
    
    if not url:
        logger.error("Error: URL parameter is missing")
        return jsonify({"error": "URL parameter is required"}), 400
    
    try:
        command = f"ping -c 1 {url}"
        logger.info(f"Executing command: {command}")
        
        # Execute the command in shell - this is the vulnerable part!
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        logger.info(f"Command completed with return code: {result.returncode}")
        logger.info(f"Command stdout: {result.stdout.strip()}")
        if result.stderr:
            logger.warning(f"Command stderr: {result.stderr.strip()}")
        
        return jsonify({
            "message": "Test connection completed",
            "original_url": url,
            "command_executed": command,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        })
        
    except subprocess.TimeoutExpired:
        logger.error("Error: Command timed out after 30 seconds")
        return jsonify({"error": "Command timed out after 30 seconds"}), 500
    except Exception as e:
        logger.error(f"Failed to execute command: {str(e)}")
        return jsonify({"error": f"Failed to execute command: {str(e)}"}), 500

if __name__ == '__main__':
    # Start the background scheduler before running the app
    start_background_scheduler()
    
    # Log app startup
    logger.info("Webhook Service is starting on host: 0.0.0.0, port: 5000")
    logger.info(f"Debug mode: {True}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)