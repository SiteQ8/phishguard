#!/usr/bin/env python3
"""
PhishGuard - Real-time Phishing Detection Dashboard
Integrates CertStream and OpenSquat for comprehensive phishing detection
"""

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import certstream
import requests
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from werkzeug.serving import run_simple

from utils.opensquat_integration import OpenSquatIntegration
from utils.domain_analyzer import DomainAnalyzer
from utils.threat_classifier import ThreatClassifier
from config.settings import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PhishDetector:
    """Main phishing detection application"""

    def __init__(self):
        self.app = Flask(__name__)
        self.app.config.from_object(Config)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        # Initialize components
        self.opensquat = OpenSquatIntegration()
        self.analyzer = DomainAnalyzer()
        self.classifier = ThreatClassifier()

        # Detection storage
        self.detections: List[Dict] = []
        self.stats = {
            'total_detections': 0,
            'critical_alerts': 0,
            'active_monitoring': False,
            'avg_risk_score': 0.0
        }

        # Monitoring state
        self.monitoring_active = False
        self.certstream_thread = None
        self.opensquat_thread = None

        self.setup_routes()
        self.setup_socketio_events()

    def setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            return render_template('dashboard.html', stats=self.stats)

        @self.app.route('/api/detections')
        def get_detections():
            # Filter by risk level and source if specified
            risk_filter = request.args.get('risk', 'all')
            source_filter = request.args.get('source', 'all')
            limit = int(request.args.get('limit', 50))

            filtered_detections = self.filter_detections(
                self.detections, risk_filter, source_filter
            )

            return jsonify({
                'detections': filtered_detections[:limit],
                'total': len(filtered_detections)
            })

        @self.app.route('/api/stats')
        def get_stats():
            return jsonify(self.calculate_stats())

        @self.app.route('/api/start_monitoring', methods=['POST'])
        def start_monitoring():
            if not self.monitoring_active:
                self.start_detection()
                return jsonify({'status': 'monitoring_started'})
            return jsonify({'status': 'already_monitoring'})

        @self.app.route('/api/stop_monitoring', methods=['POST'])
        def stop_monitoring():
            if self.monitoring_active:
                self.stop_detection()
                return jsonify({'status': 'monitoring_stopped'})
            return jsonify({'status': 'not_monitoring'})

        @self.app.route('/api/export_detections')
        def export_detections():
            # Export detections as CSV
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                'domain', 'risk_score', 'source', 'timestamp', 'similarity',
                'certificate_issuer', 'ip_address', 'country'
            ])
            writer.writeheader()

            for detection in self.detections:
                writer.writerow({
                    'domain': detection['domain'],
                    'risk_score': detection['risk_score'],
                    'source': detection['source'],
                    'timestamp': detection['timestamp'],
                    'similarity': detection['similarity'],
                    'certificate_issuer': detection.get('certificate_issuer', ''),
                    'ip_address': detection.get('ip_address', ''),
                    'country': detection.get('country', '')
                })

            return output.getvalue(), 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': 'attachment; filename=phish_detections.csv'
            }

    def setup_socketio_events(self):
        """Setup SocketIO events for real-time communication"""

        @self.socketio.on('connect')
        def handle_connect():
            logger.info('Client connected')
            emit('stats_update', self.calculate_stats())

        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info('Client disconnected')

        @self.socketio.on('request_detections')
        def handle_detection_request(data):
            filters = data.get('filters', {})
            detections = self.filter_detections(
                self.detections, 
                filters.get('risk', 'all'),
                filters.get('source', 'all')
            )
            emit('detections_update', {'detections': detections[:50]})

    def certstream_callback(self, message, context):
        """Callback for CertStream certificate updates"""
        if message['message_type'] == 'heartbeat':
            return

        if message['message_type'] == 'certificate_update':
            try:
                all_domains = message['data']['leaf_cert']['all_domains']
                cert_data = {
                    'source': message['data']['source']['name'],
                    'issuer': message['data']['leaf_cert'].get('extensions', {}).get('authorityKeyIdentifier', ''),
                    'timestamp': datetime.fromtimestamp(message['data']['seen'])
                }

                for domain in all_domains:
                    if self.is_suspicious_domain(domain):
                        detection = self.process_suspicious_domain(domain, 'CertStream', cert_data)
                        if detection:
                            self.add_detection(detection)

            except Exception as e:
                logger.error(f"Error processing certificate: {e}")

    def is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is potentially suspicious"""
        suspicious_keywords = [
            'paypal', 'microsoft', 'google', 'amazon', 'apple', 'facebook',
            'netflix', 'dropbox', 'adobe', 'zoom', 'login', 'signin', 
            'security', 'verify', 'account', 'update', 'suspend'
        ]

        domain_lower = domain.lower()
        for keyword in suspicious_keywords:
            if keyword in domain_lower and keyword != domain_lower:
                return True
        return False

    def process_suspicious_domain(self, domain: str, source: str, metadata: Dict) -> Optional[Dict]:
        """Process a suspicious domain and generate detection data"""
        try:
            # Analyze domain
            analysis = self.analyzer.analyze_domain(domain)
            risk_score = self.classifier.calculate_risk_score(domain, analysis)

            # Only process high-risk domains
            if risk_score < 50:
                return None

            detection = {
                'id': len(self.detections) + 1,
                'domain': domain,
                'risk_score': risk_score,
                'source': source,
                'timestamp': datetime.now().isoformat(),
                'similarity': analysis.get('similarity_target', ''),
                'certificate_issuer': metadata.get('issuer', ''),
                'ip_address': analysis.get('ip_address', ''),
                'country': analysis.get('country', ''),
                'status': 'active',
                'analysis': analysis
            }

            return detection

        except Exception as e:
            logger.error(f"Error processing domain {domain}: {e}")
            return None

    def add_detection(self, detection: Dict):
        """Add a new detection and broadcast to clients"""
        self.detections.insert(0, detection)  # Add to beginning

        # Keep only last 1000 detections
        if len(self.detections) > 1000:
            self.detections = self.detections[:1000]

        # Update stats
        self.stats['total_detections'] += 1
        if detection['risk_score'] >= 90:
            self.stats['critical_alerts'] += 1

        # Broadcast to all connected clients
        self.socketio.emit('new_detection', detection)
        self.socketio.emit('stats_update', self.calculate_stats())

        logger.info(f"New detection: {detection['domain']} (Risk: {detection['risk_score']})")

    def filter_detections(self, detections: List[Dict], risk_filter: str, source_filter: str) -> List[Dict]:
        """Filter detections based on criteria"""
        filtered = detections

        if risk_filter != 'all':
            if risk_filter == 'critical':
                filtered = [d for d in filtered if d['risk_score'] >= 90]
            elif risk_filter == 'high':
                filtered = [d for d in filtered if 70 <= d['risk_score'] < 90]
            elif risk_filter == 'medium':
                filtered = [d for d in filtered if 50 <= d['risk_score'] < 70]
            elif risk_filter == 'low':
                filtered = [d for d in filtered if d['risk_score'] < 50]

        if source_filter != 'all':
            filtered = [d for d in filtered if d['source'].lower() == source_filter.lower()]

        return filtered

    def calculate_stats(self) -> Dict:
        """Calculate current statistics"""
        if not self.detections:
            return self.stats

        total = len(self.detections)
        critical = len([d for d in self.detections if d['risk_score'] >= 90])
        avg_risk = sum(d['risk_score'] for d in self.detections) / total if total > 0 else 0

        # Calculate hourly distribution
        now = datetime.now()
        hourly_counts = [0] * 24
        for detection in self.detections:
            try:
                dt = datetime.fromisoformat(detection['timestamp'].replace('Z', '+00:00'))
                if (now - dt).days == 0:  # Today only
                    hourly_counts[dt.hour] += 1
            except:
                pass

        return {
            'total_detections': total,
            'critical_alerts': critical,
            'active_monitoring': self.monitoring_active,
            'avg_risk_score': round(avg_risk, 1),
            'hourly_distribution': hourly_counts,
            'recent_detections': self.detections[:5]
        }

    def start_detection(self):
        """Start the detection process"""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.stats['active_monitoring'] = True

        # Start CertStream monitoring
        self.certstream_thread = threading.Thread(
            target=self._run_certstream_monitor,
            daemon=True
        )
        self.certstream_thread.start()

        # Start OpenSquat monitoring
        self.opensquat_thread = threading.Thread(
            target=self._run_opensquat_monitor,
            daemon=True
        )
        self.opensquat_thread.start()

        logger.info("Detection monitoring started")

    def stop_detection(self):
        """Stop the detection process"""
        self.monitoring_active = False
        self.stats['active_monitoring'] = False
        logger.info("Detection monitoring stopped")

    def _run_certstream_monitor(self):
        """Run CertStream monitoring in a separate thread"""
        try:
            logger.info("Starting CertStream monitoring...")
            certstream.listen_for_events(
                self.certstream_callback,
                url='wss://certstream.calidog.io/'
            )
        except Exception as e:
            logger.error(f"CertStream monitoring error: {e}")

    def _run_opensquat_monitor(self):
        """Run OpenSquat monitoring in a separate thread"""
        try:
            logger.info("Starting OpenSquat monitoring...")
            while self.monitoring_active:
                # Run OpenSquat scan every 30 minutes
                suspicious_domains = self.opensquat.scan_recent_domains()

                for domain_data in suspicious_domains:
                    if self.monitoring_active:
                        detection = self.process_suspicious_domain(
                            domain_data['domain'], 
                            'OpenSquat',
                            domain_data
                        )
                        if detection:
                            self.add_detection(detection)

                # Wait before next scan
                for _ in range(1800):  # 30 minutes
                    if not self.monitoring_active:
                        break
                    time.sleep(1)

        except Exception as e:
            logger.error(f"OpenSquat monitoring error: {e}")

    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the application"""
        logger.info(f"Starting PhishGuard Dashboard on {host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)

# Create a global app instance for Gunicorn
detector = PhishDetector()
app = detector.app
socketio = detector.socketio

if __name__ == '__main__':
    detector.run(debug=True)
