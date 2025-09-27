# PhishGuard - Real-time Phishing Detection Dashboard

![PhishGuard Logo](https://img.shields.io/badge/PhishGuard-v2.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A comprehensive real-time phishing detection system that integrates **CertStream** and **OpenSquat** to monitor and detect suspicious domains as they appear. Features a modern web dashboard with real-time updates, threat classification, and comprehensive domain analysis.

## ✨ Features

### 🎯 Real-time Detection
- **CertStream Integration**: Monitor SSL certificates as they're issued in real-time
- **OpenSquat Integration**: Detect domain squatting and typosquatting
- **Live Dashboard**: Real-time updates without page refresh using WebSockets
- **Multi-source Detection**: Combines multiple detection methods for comprehensive coverage
- **Demo**: https://3li.info/PhishGuard/

### 🧠 Intelligent Analysis
- **Risk Scoring**: Machine learning-inspired risk calculation (0-100 scale)
- **Brand Similarity Detection**: Identify domains impersonating known brands
- **Pattern Analysis**: Detect suspicious domain patterns and structures
- **DNS Analysis**: Technical analysis of domain infrastructure
- **Threat Classification**: Automatic categorization (Critical, High, Medium, Low)

### 📊 Professional Dashboard
- **Real-time Feed**: Live stream of detected phishing domains
- **Interactive Charts**: Detection trends and risk distribution
- **Filtering & Search**: Advanced filtering by risk level, source, and time
- **Export Capabilities**: Export detection data in CSV, JSON formats
- **Alert System**: Real-time notifications for high-risk detections

### 🔧 Enterprise Features
- **Keyword Management**: Customize monitoring for specific brands
- **API Endpoints**: RESTful API for integration with other security tools
- **Scalable Architecture**: Designed for high-volume certificate processing
- **Configurable Thresholds**: Adjust sensitivity and risk scoring parameters

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SiteQ8/phishguard.git
   cd phish_detector
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install OpenSquat (optional for manual installation):**
   ```bash
   git clone https://github.com/atenreiro/opensquat.git
   cd opensquat
   pip install -r requirements.txt
   cd ..
   ```
   **Note:** OpenSquat is automatically included in Docker deployments.

4. **Run the application:**
   ```bash
   python app.py
   ```

5. **Access the dashboard:**
   Open your browser and navigate to `http://localhost:5000`

## 📖 Usage Guide

### Starting Monitoring
1. Click the "Start Monitoring" button in the dashboard header
2. The system will begin monitoring CertStream and OpenSquat feeds
3. Detected domains will appear in real-time in the detection feed

### Understanding Risk Scores
- **90-100 (Critical)**: High confidence phishing domains, immediate action required
- **70-89 (High)**: Strong phishing indicators, blocking recommended
- **50-69 (Medium)**: Suspicious characteristics, monitoring recommended
- **0-49 (Low)**: Minor suspicious elements, continued observation

### Filtering Detections
- Use the risk level filter to focus on high-priority threats
- Filter by source (CertStream vs OpenSquat) to analyze detection methods
- Export filtered results for further analysis

### Managing Keywords
- Add custom keywords to monitor specific brands or terms
- Keywords are used by both CertStream and OpenSquat for targeted detection
- Remove keywords that generate too many false positives

## 🏗️ Architecture

### Core Components

```
phish_detector/
├── app.py                     # Main Flask application with SocketIO
├── config/
│   └── settings.py           # Configuration management
├── utils/
│   ├── opensquat_integration.py    # OpenSquat API integration
│   ├── domain_analyzer.py          # Domain analysis engine
│   └── threat_classifier.py        # Risk scoring and classification
├── templates/
│   └── dashboard.html              # Web dashboard template
├── static/
│   ├── css/dashboard.css           # Dashboard styling
│   └── js/dashboard.js             # Frontend JavaScript
└── requirements.txt                # Python dependencies
```

### Data Flow
1. **CertStream** provides real-time SSL certificate data via WebSocket
2. **OpenSquat** scans for newly registered suspicious domains
3. **Domain Analyzer** performs technical analysis (DNS, WHOIS, patterns)
4. **Threat Classifier** calculates risk scores using multiple factors
5. **Flask-SocketIO** broadcasts detections to connected clients in real-time
6. **Dashboard** displays live feed with filtering and analysis tools

## 🔧 Configuration

### Environment Variables
```bash
# Flask configuration
SECRET_KEY=your-secret-key-here
LOG_LEVEL=INFO

# Monitoring settings
CERTSTREAM_URL=wss://certstream.calidog.io/
OPENSQUAT_SCAN_INTERVAL=1800

# Risk thresholds
CRITICAL_RISK_THRESHOLD=90
HIGH_RISK_THRESHOLD=70
MEDIUM_RISK_THRESHOLD=50
```

### Custom Keywords
Edit the keywords list in `config/settings.py` or manage them through the dashboard:
```python
DEFAULT_KEYWORDS = [
    'paypal', 'microsoft', 'google', 'amazon', 'apple',
    'your-company-name', 'your-brand'
]
```

## 📡 API Reference

### Get Detections
```http
GET /api/detections?risk=high&source=certstream&limit=50
```

### Get Statistics
```http
GET /api/stats
```

### Start/Stop Monitoring
```http
POST /api/start_monitoring
POST /api/stop_monitoring
```

### Export Data
```http
GET /api/export_detections
```

## 🚀 Deployment

### Development
```bash
python app.py
```

### Production with Gunicorn
```bash
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

### Docker Deployment

PhishGuard includes full Docker support for easy deployment and containerization.

#### Quick Start with Docker Compose
```bash
# Build and run with docker-compose
make run
# or manually:
docker-compose up -d --build

# View logs
make logs
# or manually:
docker-compose logs -f

# Stop the application
make stop
# or manually:
docker-compose down
```

#### Manual Docker Build
```bash
# Build the Docker image
make build
# or manually:
docker build -t phishguard:latest .

# Run the container
docker run -d -p 8080:5000 --name phishguard phishguard:latest
```

#### Environment Configuration
Create a `.env` file (copy from `.env.example`) to configure:
- `LOG_LEVEL`: Logging level (INFO, DEBUG, WARNING)
- `SECRET_KEY`: Flask secret key for sessions
- `CERTSTREAM_URL`: CertStream WebSocket URL
- `OPENSQUAT_PATH`: Path to OpenSquat executable (auto-configured in Docker)
- Risk thresholds and other settings

#### Integrated Components
The Docker deployment includes:
- **OpenSquat**: Automatically installed and configured at `/opt/opensquat/opensquat.py`
- **All Dependencies**: No manual dependency management required
- **Optimized Configuration**: Pre-configured for best performance

#### Access the Application
After starting with Docker, access the dashboard at: http://localhost:8080

**Note**: The default port mapping is 8080:5000 to avoid conflicts with other services.

#### Verify OpenSquat Integration
To verify that OpenSquat is properly integrated in the Docker container:
```bash
# Check container logs for OpenSquat detection
docker logs phishguard | grep opensquat_integration

# Test OpenSquat directly in the container
docker exec phishguard python3 /opt/opensquat/opensquat.py --help

# Verify the integration path
docker exec phishguard ls -la /opt/opensquat/opensquat.py
```

## 🔒 Security Considerations

- **Rate Limiting**: Implement rate limiting for API endpoints in production
- **Authentication**: Add user authentication for sensitive deployments
- **HTTPS**: Use HTTPS in production environments
- **Data Retention**: Configure appropriate data retention policies
- **Access Control**: Restrict access to admin functions

## 🤝 Integration with Security Tools

### SIEM Integration
Export detection data to your SIEM using the CSV/JSON export feature or API endpoints.

### Email Alerts
Integrate with email systems to send alerts for critical detections:
```python
# Add to your monitoring loop
if detection['risk_score'] >= CRITICAL_THRESHOLD:
    send_email_alert(detection)
```

### DNS Sinkholes
Use detection data to automatically update DNS sinkholes:
```python
# Example integration
def update_dns_sinkhole(domain):
    # Add domain to your DNS filtering system
    pass
```

## 📊 Performance

### Scalability
- Handles 200+ certificates per second from CertStream
- Processes thousands of domains per hour
- Real-time updates to multiple connected clients
- Configurable retention (default: 1000 recent detections)

### Resource Usage
- CPU: Moderate (depends on detection volume)
- Memory: ~100MB base + ~1MB per 1000 detections
- Network: Continuous WebSocket connection to CertStream
- Storage: Minimal (in-memory storage by default)

## 🛠️ Troubleshooting

### Common Issues

**CertStream Connection Issues:**
```bash
# Check network connectivity
curl -I https://certstream.calidog.io
# Verify WebSocket connection
python -c "import certstream; print('CertStream available')"
```

**OpenSquat Not Found:**
```bash
# Install OpenSquat manually
git clone https://github.com/atenreiro/opensquat.git
# Update path in opensquat_integration.py
```

**High False Positives:**
- Adjust risk thresholds in configuration
- Refine keyword list
- Update similarity detection algorithms

## 🔮 Future Enhancements

- [ ] Machine learning model training on historical phishing data
- [ ] Integration with threat intelligence feeds
- [ ] Advanced visualization and reporting
- [ ] Mobile app for real-time alerts
- [ ] Multi-tenant support for MSSPs
- [ ] Integration with popular security platforms (Splunk, ELK, etc.)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **CertStream** by CaliDog Security for real-time certificate transparency
- **OpenSquat** by Andre Tenreiro for domain squatting detection
- **Flask-SocketIO** for real-time web communication
- The cybersecurity community for threat intelligence and research

## 📞 Support

For support, please:
1. Check the troubleshooting section above
2. Review existing GitHub issues
3. Create a new issue with detailed information
4. Contact the development team

---

**Built with ❤️ for the cybersecurity community**

*Protecting organizations from phishing attacks, one domain at a time.*
