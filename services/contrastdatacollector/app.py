#!/usr/bin/env python3
"""
Contrast Data Collector Service
Collects data from Contrast Security APIs and logs to files for Fluent Bit collection
"""

import os
import json
import time
import logging
import requests
import base64
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import schedule
from flask import Flask, jsonify, request
import threading

# Configure main application logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app for health checks and manual triggers
app = Flask(__name__)

# Setup specialized loggers for data collection
def setup_data_logger(name: str):
    """Setup a logger that writes JSON data to stdout for Fluent Bit collection"""
    data_logger = logging.getLogger(name)
    data_logger.setLevel(logging.INFO)
    
    # Remove any existing handlers
    data_logger.handlers.clear()
    
    # Create console handler to write to stdout
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    
    # Create formatter for JSON logging
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    
    data_logger.addHandler(handler)
    data_logger.propagate = False  # Don't propagate to root logger
    
    return data_logger

# Setup data loggers
issues_logger = setup_data_logger('contrast.issues')
incidents_logger = setup_data_logger('contrast.incidents')

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

class ContrastDataCollector:
    def __init__(self):
        # Data collection configuration
        self.collection_interval_seconds = int(os.getenv('COLLECTION_INTERVAL_SECONDS', '20'))
        self.application_name = os.getenv('CONTRAST_UNIQ_NAME', 'graphtest')
        self.max_consecutive_failures = int(os.getenv('MAX_CONSECUTIVE_FAILURES', '5'))
        
        # In-memory tracking for duplicate prevention
        self.seen_issue_ids = set()
        self.seen_incident_ids = set()
        
        # Failure tracking with timed retry mechanism
        # Instead of permanently pausing on failures, we pause for a configurable period
        self.consecutive_issues_failures = 0
        self.consecutive_incidents_failures = 0
        self.issues_paused_until = None  # UTC timestamp when pause expires
        self.incidents_paused_until = None  # UTC timestamp when pause expires
        self.retry_interval_minutes = int(os.getenv('RETRY_INTERVAL_MINUTES', '5'))  # How long to pause before retrying
        
        # Parse organization ID and base URL from API token
        api_token = os.getenv('CONTRAST__AGENT__TOKEN')
        if not api_token:
            raise ValueError("CONTRAST__AGENT__TOKEN environment variable is required")
            
        token_info = parse_contrast_token(api_token)
        if not token_info:
            raise ValueError("Could not parse organization ID and base URL from API token")
            
        self.org_id = token_info['org_id']
        self.base_url = token_info['base_url']
        
        # API endpoints
        self.issues_endpoint = f"{self.base_url}/api/ns-ui/v1/organizations/{self.org_id}/issues"
        self.incidents_endpoint = f"{self.base_url}/api/ns-ui/v1/organizations/{self.org_id}/incidents"
        
        # Request parameters for URL
        self.issues_params = {
            'page': 0,
            'size': 100,
            'sort': ['status,desc', 'cvssScore,desc', 'lastObservationAt,desc']
        }
        
        self.incidents_params = {
            'page': 0,
            'size': 100,
            'sort': ['status,desc', 'cvssScore,desc', 'updatedDt,desc']
        }
        
        # Request body for POST requests
        self.request_body = {
            'applicationName': self.application_name
        }
        
        # Setup session with headers
        self.session = requests.Session()
        
        # Get authentication credentials from environment variables
        api_key = os.getenv('CONTRAST__API__KEY')
        api_authorization = os.getenv('CONTRAST__API__AUTHORIZATION')
        
        # Validate required API credentials
        if not api_key:
            raise ValueError("CONTRAST__API__KEY environment variable is required")
        if not api_authorization:
            raise ValueError("CONTRAST__API__AUTHORIZATION environment variable is required")
        
        logger.info(f"Loaded CONTRAST__API__KEY: {api_key}")
        logger.info(f"Loaded CONTRAST__API__AUTHORIZATION: {'***' if api_authorization else None}")
        
        # Setup headers with API authentication only
        headers = {
            'User-Agent': 'ContrastDataCollector/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'API-Key': api_key,
            'Authorization': api_authorization
        }
        
        self.session.headers.update(headers)
        
        logger.info(f"Contrast Data Collector initialized for application: {self.application_name}, org: {self.org_id}, base_url: {self.base_url}")
    
    def is_issues_paused(self) -> bool:
        """Check if issues collection is currently paused"""
        if self.issues_paused_until is None:
            return False
        
        current_time = datetime.now(timezone.utc)
        if current_time >= self.issues_paused_until:
            # Timeout expired, reset failure counter and resume
            self.issues_paused_until = None
            self.consecutive_issues_failures = 0
            logger.info("Issues collection timeout expired, resuming data collection")
            return False
        
        return True
    
    def is_incidents_paused(self) -> bool:
        """Check if incidents collection is currently paused"""
        if self.incidents_paused_until is None:
            return False
        
        current_time = datetime.now(timezone.utc)
        if current_time >= self.incidents_paused_until:
            # Timeout expired, reset failure counter and resume
            self.incidents_paused_until = None
            self.consecutive_incidents_failures = 0
            logger.info("Incidents collection timeout expired, resuming data collection")
            return False
        
        return True

    def collect_issues(self) -> bool:
        # Check if issues collection is paused due to consecutive failures
        if self.is_issues_paused():
            time_remaining = (self.issues_paused_until - datetime.now(timezone.utc)).total_seconds()
            logger.warning(f"Issues collection is paused due to {self.consecutive_issues_failures} consecutive failures. Retrying in {int(time_remaining/60)} minutes")
            return False

        try:
            response = self.session.post(
                self.issues_endpoint,
                params=self.issues_params,
                json=self.request_body,
                timeout=30
            )
            response_time = response.elapsed.total_seconds() * 1000
            log_entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'contrast-security-api',
                'data_type': 'issues',
                'log_type': 'contrast-issues-summary',
                'endpoint': self.issues_endpoint,
                'application': self.application_name,
                'response_time_ms': int(response_time),
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            if response.status_code == 200:
                data = response.json()
                issues_data = data['issues']
                new_issues = []
                new_observations_of_existing_issues = []
                duplicate_count = 0
                missing_id_count = 0

                now = datetime.now(timezone.utc)
                cutoff_time = now - timedelta(seconds=self.collection_interval_seconds)

                for issue in issues_data:
                    issue_id = issue.get('issueId')
                    last_obs_time_str = issue.get('lastObservationTime')
                    last_obs_time = None

                    # Parse lastObservationTime if present
                    if last_obs_time_str:
                        try:
                            last_obs_time = datetime.fromisoformat(last_obs_time_str.replace('Z', '+00:00'))
                        except Exception:
                            logger.warning(f"Could not parse lastObservationTime for issue {issue_id}: {last_obs_time_str}")

                    if issue_id:
                        # NEW issue
                        if issue_id not in self.seen_issue_ids:
                            new_issues.append(issue)
                            self.seen_issue_ids.add(issue_id)

                        # EXISTING issue - check if this is a new observation
                        elif last_obs_time and last_obs_time >= cutoff_time:
                            new_observations_of_existing_issues.append(issue)

                        # EXISTING but *not* recent → count as duplicate & ignore
                        else:
                            duplicate_count += 1

                    else:
                        # Missing issueId case
                        missing_id_count += 1
                        logger.warning(f"Issue missing ID: {issue.get('issueName', 'Unknown')}")

                log_entry['total_count'] = len(issues_data)
                log_entry['new_count'] = len(new_issues)
                log_entry['new_observation_count'] = len(new_observations_of_existing_issues)
                log_entry['duplicate_count'] = duplicate_count
                log_entry['missing_id_count'] = missing_id_count

                logger.info(
                    f"Collected {len(issues_data)} issues "
                    f"({len(new_issues)} new, "
                    f"{len(new_observations_of_existing_issues)} new observations of existing issues, "
                    f"{duplicate_count} duplicates, {missing_id_count} missing IDs)"
                )

                # Process new issues
                for issue in new_issues:
                    issue_log = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'source': 'contrast-security-api',
                        'data_type': 'issue',
                        'log_type': 'contrast-issues',
                        'event': 'new_issue',
                        'issue_id': issue.get('issueId'),
                        'issue_title': issue.get('issueName'),
                        'issue_status': issue.get('status'),
                        'cvss_score': issue.get('score'),
                        'severity': issue.get('severity'),
                        'last_observation': issue.get('lastObservationTime'),
                        'application_id': issue.get('applicationId'),
                        'application_name': issue.get('applicationName'),
                        'incident_id': issue.get('incidentId'),
                        'incident_name': issue.get('incidentName'),
                        'observation_count': issue.get('observationCount'),
                        'full_data': issue
                    }
                    issues_logger.info(json.dumps(issue_log))


                # Process *new observations of existing issues*
                for issue in new_observations_of_existing_issues:
                    issue_log = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'source': 'contrast-security-api',
                        'data_type': 'issue',
                        'log_type': 'contrast-issues',
                        'event': 'new_observation',
                        'issue_id': issue.get('issueId'),
                        'issue_title': issue.get('issueName'),
                        'issue_status': issue.get('status'),
                        'cvss_score': issue.get('score'),
                        'severity': issue.get('severity'),
                        'last_observation': issue.get('lastObservationTime'),
                        'application_id': issue.get('applicationId'),
                        'application_name': issue.get('applicationName'),
                        'incident_id': issue.get('incidentId'),
                        'incident_name': issue.get('incidentName'),
                        'observation_count': issue.get('observationCount'),
                        'full_data': issue
                    }
                    issues_logger.info(json.dumps(issue_log))
            else:
                log_entry['error'] = f"HTTP {response.status_code}: {response.text}"
                logger.warning(f"Issues API call failed: {log_entry['error']}")
                self.consecutive_issues_failures += 1
                if self.consecutive_issues_failures >= self.max_consecutive_failures:
                    self.issues_paused_until = datetime.now(timezone.utc) + timedelta(minutes=self.retry_interval_minutes)
                    logger.error(f"Issues collection paused for {self.retry_interval_minutes} minutes after {self.consecutive_issues_failures} consecutive failures. Will retry at {self.issues_paused_until.isoformat()}")
                return False
            
            # Success - reset failure counter and clear any pause
            self.consecutive_issues_failures = 0
            self.issues_paused_until = None
            return True
        except Exception as e:
            error_log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'contrast-security-api',
                'data_type': 'issues',
                'endpoint': self.issues_endpoint,
                'error': str(e),
                'success': False
            }
            issues_logger.error(json.dumps(error_log))
            logger.error(f"Error collecting issues: {e}")
            
            # Count as a failure
            self.consecutive_issues_failures += 1
            if self.consecutive_issues_failures >= self.max_consecutive_failures:
                self.issues_paused_until = datetime.now(timezone.utc) + timedelta(minutes=self.retry_interval_minutes)
                logger.error(f"Issues collection paused for {self.retry_interval_minutes} minutes after {self.consecutive_issues_failures} consecutive failures. Will retry at {self.issues_paused_until.isoformat()}")
                
            return False

    def collect_incidents(self) -> bool:
        # Check if incidents collection is paused due to consecutive failures
        if self.is_incidents_paused():
            time_remaining = (self.incidents_paused_until - datetime.now(timezone.utc)).total_seconds()
            logger.warning(f"Incidents collection is paused due to {self.consecutive_incidents_failures} consecutive failures. Retrying in {int(time_remaining/60)} minutes")
            return False
            
        try:
            response = self.session.post(
                self.incidents_endpoint,
                params=self.incidents_params,
                json=self.request_body,
                timeout=30
            )
            response_time = response.elapsed.total_seconds() * 1000
            log_entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'contrast-security-api',
                'data_type': 'incidents',
                'log_type': 'contrast-incidents-summary',
                'endpoint': self.incidents_endpoint,
                'application': self.application_name,
                'response_time_ms': int(response_time),
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            if response.status_code == 200:
                data = response.json()
                incidents_data = data['incidents']
                new_incidents = []
                new_observations_of_existing_incidents = []
                duplicate_count = 0
                missing_id_count = 0

                now = datetime.now(timezone.utc)
                cutoff_time = now - timedelta(seconds=self.collection_interval_seconds)

                for incident in incidents_data:
                    incident_id = incident.get('incidentId')
                    last_obs_time_str = incident.get('lastObservationTime')
                    last_obs_time = None

                    # Parse lastObservationTime if present
                    if last_obs_time_str:
                        try:
                            last_obs_time = datetime.fromisoformat(last_obs_time_str.replace('Z', '+00:00'))
                        except Exception:
                            logger.warning(f"Could not parse lastObservationTime for incident {incident_id}: {last_obs_time_str}")

                    if incident_id:
                        # NEW incident
                        if incident_id not in self.seen_incident_ids:
                            new_incidents.append(incident)
                            self.seen_incident_ids.add(incident_id)

                        # EXISTING incident - check if this is a new observation
                        elif last_obs_time and last_obs_time >= cutoff_time:
                            new_observations_of_existing_incidents.append(incident)

                        # EXISTING but *not* recent → count as duplicate & ignore
                        else:
                            duplicate_count += 1

                    else:
                        # Missing incidentId case
                        missing_id_count += 1
                        logger.warning(f"Incident missing ID: {incident.get('incidentName', 'Unknown')}")

                log_entry['total_count'] = len(incidents_data)
                log_entry['new_count'] = len(new_incidents)
                log_entry['new_observation_count'] = len(new_observations_of_existing_incidents)
                log_entry['duplicate_count'] = duplicate_count
                log_entry['missing_id_count'] = missing_id_count

                logger.info(
                    f"Collected {len(incidents_data)} incidents "
                    f"({len(new_incidents)} new, "
                    f"{len(new_observations_of_existing_incidents)} new observations of existing incidents, "
                    f"{duplicate_count} duplicates, {missing_id_count} missing IDs)"
                )

                for i, incident in enumerate(new_incidents):
                    incident_log = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'source': 'contrast-security-api',
                        'data_type': 'incident',
                        'log_type': 'contrast-incidents',
                        'event': 'new_incident',
                        'incident_index': i,
                        'incident_id': incident.get('incidentId'),
                        'incident_title': incident.get('incidentName'),
                        'incident_status': incident.get('status'),
                        'cvss_score': incident.get('score'),
                        'severity': incident.get('severity'),
                        'created_time': incident.get('createdTime'),
                        'updated_time': incident.get('updatedTime'),
                        'assigned_user': incident.get('assignedUserName'),
                        'application_count': incident.get('applicationCount'),
                        'asset_count': incident.get('assetCount'),
                        'full_data': incident
                    }
                    incidents_logger.info(json.dumps(incident_log))

                # Process *new observations of existing incidents*
                for i, incident in enumerate(new_observations_of_existing_incidents):
                    incident_log = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'source': 'contrast-security-api',
                        'data_type': 'incident',
                        'log_type': 'contrast-incidents',
                        'event': 'new_observation',
                        'incident_index': i,
                        'incident_id': incident.get('incidentId'),
                        'incident_title': incident.get('incidentName'),
                        'incident_status': incident.get('status'),
                        'cvss_score': incident.get('score'),
                        'severity': incident.get('severity'),
                        'created_time': incident.get('createdTime'),
                        'updated_time': incident.get('updatedTime'),
                        'assigned_user': incident.get('assignedUserName'),
                        'application_count': incident.get('applicationCount'),
                        'asset_count': incident.get('assetCount'),
                        'full_data': incident
                    }
                    incidents_logger.info(json.dumps(incident_log))

            else:
                log_entry['error'] = f"HTTP {response.status_code}: {response.text}"
                logger.warning(f"Incidents API call failed: {log_entry['error']}")
                self.consecutive_incidents_failures += 1
                if self.consecutive_incidents_failures >= self.max_consecutive_failures:
                    self.incidents_paused_until = datetime.now(timezone.utc) + timedelta(minutes=self.retry_interval_minutes)
                    logger.error(f"Incidents collection paused for {self.retry_interval_minutes} minutes after {self.consecutive_incidents_failures} consecutive failures. Will retry at {self.incidents_paused_until.isoformat()}")
                return False
            
            # Success - reset failure counter and clear any pause
            self.consecutive_incidents_failures = 0
            self.incidents_paused_until = None
            return True
        except Exception as e:
            error_log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'contrast-security-api',
                'data_type': 'incidents',
                'endpoint': self.incidents_endpoint,
                'error': str(e),
                'success': False
            }
            incidents_logger.error(json.dumps(error_log))
            logger.error(f"Error collecting incidents: {e}")
            
            # Count as a failure
            self.consecutive_incidents_failures += 1
            if self.consecutive_incidents_failures >= self.max_consecutive_failures:
                self.incidents_paused_until = datetime.now(timezone.utc) + timedelta(minutes=self.retry_interval_minutes)
                logger.error(f"Incidents collection paused for {self.retry_interval_minutes} minutes after {self.consecutive_incidents_failures} consecutive failures. Will retry at {self.incidents_paused_until.isoformat()}")
                
            return False
    
    def collect_all_data(self):
        """Collect all data from APIs"""
        logger.info("Starting data collection cycle")
        
        # Collect issues
        issues_success = self.collect_issues()
        
        # Collect incidents
        incidents_success = self.collect_incidents()
        
        # Log collection summary
        summary = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'contrast-data-collector',
            'data_type': 'collection_summary',
            'issues_success': issues_success,
            'incidents_success': incidents_success,
            'collection_cycle_completed': True
        }
        
        logger.info(json.dumps(summary))
        logger.info("Data collection cycle completed")
    
    def get_tracking_stats(self):
        """Get statistics about tracked IDs"""
        return {
            'tracked_issue_ids': len(self.seen_issue_ids),
            'tracked_incident_ids': len(self.seen_incident_ids),
            'total_tracked_items': len(self.seen_issue_ids) + len(self.seen_incident_ids)
        }
    
    def clear_tracking(self):
        """Clear all tracked IDs (useful for testing or reset)"""
        self.seen_issue_ids.clear()
        self.seen_incident_ids.clear()
        logger.info("Cleared all tracked IDs")
        
    def reset_failure_counters(self):
        """Reset failure counters and resume data collection"""
        self.consecutive_issues_failures = 0
        self.consecutive_incidents_failures = 0
        self.issues_paused_until = None
        self.incidents_paused_until = None
        logger.info("Reset failure counters and resumed data collection")

# Global collector instance
collector = ContrastDataCollector()

def run_collection_job():
    """Run the data collection job"""
    try:
        collector.collect_all_data()
    except Exception as e:
        logger.error(f"Error in collection job: {e}")

def run_scheduler():
    """Run the scheduler in a separate thread"""
    logger.info(f"Starting scheduler with {collector.collection_interval_seconds} second intervals")
    schedule.every(collector.collection_interval_seconds).seconds.do(run_collection_job)

    # Run immediately on startup
    run_collection_job()

    while True:
        schedule.run_pending()
        time.sleep(1)  # Check every second for short intervals

# Flask routes for manual triggers
@app.route('/collect', methods=['POST'])
def manual_collect():
    """Manually trigger data collection"""
    try:
        run_collection_job()
        return jsonify({'status': 'success', 'message': 'Data collection triggered'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/status')
def status():
    """Get collector status"""
    tracking_stats = collector.get_tracking_stats()
    return jsonify({
        'collection_interval_seconds': collector.collection_interval_seconds,
        'output_mode': 'stdout',
        'timestamp': datetime.now().isoformat(),
        'duplicate_tracking': tracking_stats,
        'issues_status': {
            'consecutive_failures': collector.consecutive_issues_failures,
            'paused': collector.is_issues_paused(),
            'paused_until': collector.issues_paused_until.isoformat() if collector.issues_paused_until else None,
            'max_failures_allowed': collector.max_consecutive_failures
        },
        'incidents_status': {
            'consecutive_failures': collector.consecutive_incidents_failures,
            'paused': collector.is_incidents_paused(),
            'paused_until': collector.incidents_paused_until.isoformat() if collector.incidents_paused_until else None,
            'max_failures_allowed': collector.max_consecutive_failures
        },
        'retry_interval_minutes': collector.retry_interval_minutes
    })

@app.route('/logs')
def list_logs():
    """List log output mode"""
    return jsonify({
        'output_mode': 'stdout',
        'description': 'Logs are written to stdout and collected by Fluent Bit'
    })

@app.route('/clear-tracking', methods=['POST'])
def clear_tracking():
    """Clear tracked IDs (useful for testing or reset)"""
    try:
        collector.clear_tracking()
        return jsonify({'status': 'success', 'message': 'Tracking cleared'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/reset-failures', methods=['POST'])
def reset_failures():
    """Reset failure counters and resume data collection"""
    try:
        collector.reset_failure_counters()
        return jsonify({
            'status': 'success', 
            'message': 'Failure counters reset and data collection resumed',
            'issues_paused': collector.is_issues_paused(),
            'incidents_paused': collector.is_incidents_paused()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Contrast Data Collector Service")
    logger.info(f"Output mode: stdout (for Fluent Bit collection)")
    logger.info(f"Collection interval: {collector.collection_interval_seconds} seconds")

    # Start the scheduler in a background thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    # Start the Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
