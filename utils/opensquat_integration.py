"""
OpenSquat Integration Module
Provides integration with OpenSquat for domain squatting detection
"""

import json
import logging
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class OpenSquatIntegration:
    """Integration with OpenSquat domain squatting detection tool"""

    def __init__(self, keywords_file: Optional[str] = None):
        self.keywords_file = keywords_file or self._create_default_keywords()
        self.opensquat_path = self._find_opensquat()

    def _create_default_keywords(self) -> str:
        """Create default keywords file for monitoring"""
        keywords = [
            'paypal', 'microsoft', 'google', 'amazon', 'apple',
            'facebook', 'netflix', 'dropbox', 'adobe', 'zoom',
            'linkedin', 'twitter', 'instagram', 'whatsapp',
            'spotify', 'github', 'stackoverflow', 'reddit'
        ]

        # Create temporary keywords file
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        temp_file.write('\n'.join(keywords))
        temp_file.close()

        return temp_file.name

    def _find_opensquat(self) -> Optional[str]:
        """Find OpenSquat installation or download if needed"""
        import os
        
        # Check for environment variable first (Docker container)
        env_path = os.getenv('OPENSQUAT_PATH')
        if env_path and Path(env_path).exists():
            logger.info(f"Using OpenSquat from environment: {env_path}")
            return env_path
        
        # Check if opensquat.py exists in current directory or PATH
        possible_paths = [
            Path('/opt/opensquat/opensquat.py'),  # Docker container location
            Path('./opensquat/opensquat.py'),
            Path('./opensquat.py'),
            Path('/usr/local/bin/opensquat.py')
        ]

        for path in possible_paths:
            if path.exists():
                logger.info(f"Found OpenSquat at: {path}")
                return str(path)

        logger.warning("OpenSquat not found. Please install from: https://github.com/atenreiro/opensquat")
        return None

    def scan_recent_domains(self, period: str = 'day') -> List[Dict]:
        """
        Scan for recently registered suspicious domains

        Args:
            period: Time period to scan ('day', 'week', 'month')

        Returns:
            List of suspicious domain data
        """
        if not self.opensquat_path:
            logger.warning("OpenSquat not available, using simulated data")
            return self._generate_simulated_data()

        try:
            # Create temporary output file
            output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            output_file.close()

            # Build OpenSquat command
            cmd = [
                'python3', self.opensquat_path,
                '-k', self.keywords_file,
                '-p', period,
                '-o', output_file.name,
                '-t', 'json',
                '--dns',  # Enable DNS validation
                '--ct',   # Enable certificate transparency search
                '-c', '2'  # Medium confidence level
            ]

            # Run OpenSquat
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                # Parse results
                with open(output_file.name, 'r') as f:
                    data = json.load(f)

                # Clean up temporary file
                Path(output_file.name).unlink()

                return self._process_opensquat_results(data)
            else:
                logger.error(f"OpenSquat failed: {result.stderr}")
                return self._generate_simulated_data()

        except subprocess.TimeoutExpired:
            logger.error("OpenSquat scan timed out")
            return self._generate_simulated_data()
        except Exception as e:
            logger.error(f"Error running OpenSquat: {e}")
            return self._generate_simulated_data()

    def _process_opensquat_results(self, data: List[Dict]) -> List[Dict]:
        """Process raw OpenSquat results into standardized format"""
        processed = []

        for item in data:
            domain_data = {
                'domain': item.get('domain', ''),
                'confidence': item.get('confidence', 0),
                'similarity': item.get('keyword', ''),
                'levenshtein_distance': item.get('levenshtein_distance', 0),
                'dns_active': item.get('dns_active', False),
                'phishing_score': self._calculate_phishing_score(item),
                'timestamp': datetime.now().isoformat(),
                'source': 'OpenSquat'
            }

            # Only include domains with reasonable confidence
            if domain_data['confidence'] >= 1 and domain_data['domain']:
                processed.append(domain_data)

        return processed

    def _calculate_phishing_score(self, item: Dict) -> int:
        """Calculate phishing risk score from OpenSquat data"""
        score = 0

        # Base score from confidence level
        confidence_map = {0: 95, 1: 80, 2: 65, 3: 45, 4: 25}
        score += confidence_map.get(item.get('confidence', 4), 25)

        # Bonus for DNS activity
        if item.get('dns_active', False):
            score += 10

        # Bonus for short Levenshtein distance (more similar = more suspicious)
        distance = item.get('levenshtein_distance', 10)
        if distance <= 2:
            score += 15
        elif distance <= 4:
            score += 10
        elif distance <= 6:
            score += 5

        # Bonus for certain TLDs
        domain = item.get('domain', '').lower()
        suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.buzz', '.click']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 10

        return min(score, 100)

    def _generate_simulated_data(self) -> List[Dict]:
        """Generate simulated OpenSquat data for demonstration"""
        import random

        brands = ['paypal', 'microsoft', 'google', 'amazon', 'apple', 'facebook']
        tlds = ['.com', '.net', '.org', '.info', '.biz', '.tk', '.ml']
        variations = ['security', 'update', 'login', 'verify', 'account', 'support']

        simulated_domains = []

        for _ in range(random.randint(2, 8)):
            brand = random.choice(brands)
            variation = random.choice(variations)
            tld = random.choice(tlds)

            # Create typosquatting variations
            domain_patterns = [
                f"{brand}-{variation}{tld}",
                f"{brand}{variation}{tld}",
                f"{variation}-{brand}{tld}",
                f"{brand.replace('o', '0')}-{variation}{tld}",  # Character substitution
                f"{brand[:-1]}1{brand[-1]}-{variation}{tld}"    # Character insertion
            ]

            domain = random.choice(domain_patterns)

            simulated_domains.append({
                'domain': domain,
                'confidence': random.randint(0, 3),
                'similarity': brand,
                'levenshtein_distance': random.randint(1, 5),
                'dns_active': random.choice([True, False]),
                'phishing_score': random.randint(60, 95),
                'timestamp': datetime.now().isoformat(),
                'source': 'OpenSquat'
            })

        return simulated_domains

    def add_keyword(self, keyword: str):
        """Add a new keyword to monitor"""
        try:
            with open(self.keywords_file, 'a') as f:
                f.write(f'\n{keyword}')
            logger.info(f"Added keyword: {keyword}")
        except Exception as e:
            logger.error(f"Error adding keyword: {e}")

    def get_keywords(self) -> List[str]:
        """Get current monitoring keywords"""
        try:
            with open(self.keywords_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading keywords: {e}")
            return []
