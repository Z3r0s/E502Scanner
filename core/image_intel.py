"""
Image Intelligence Module for E502 OSINT Terminal
Provides automated image analysis capabilities including EXIF data extraction,
reverse image search, geolocation analysis, and hidden content detection.
Built by z3r0s / Error502
"""

import os
import requests
from PIL import Image
from PIL.ExifTags import TAGS
import piexif
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
from datetime import datetime
import hashlib
import base64
from io import BytesIO
import cv2
import numpy as np
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import stegano
from stegano import lsb
import imagehash
from imagehash import average_hash, phash, dhash, whash

console = Console()

class ImageIntelligence:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.geolocator = Nominatim(user_agent="E502OSINT")
        
    def analyze_image(self, image_path: str) -> Dict:
        """Perform comprehensive image analysis."""
        try:
            analysis = {
                'image_path': image_path,
                'timestamp': datetime.now().isoformat(),
                'basic_info': self._get_basic_info(image_path),
                'exif_data': self._extract_exif(image_path),
                'geolocation': self._analyze_geolocation(image_path),
                'hidden_content': self._check_hidden_content(image_path),
                'similar_images': self._find_similar_images(image_path),
                'image_hash': self._generate_image_hash(image_path)
            }
            
            return analysis
        except Exception as e:
            console.print(f"[red]Error during image analysis: {str(e)}[/]")
            return {}

    def _get_basic_info(self, image_path: str) -> Dict:
        """Get basic image information."""
        try:
            with Image.open(image_path) as img:
                info = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size,
                    'width': img.width,
                    'height': img.height,
                    'file_size': os.path.getsize(image_path),
                    'created_date': datetime.fromtimestamp(os.path.getctime(image_path)).isoformat(),
                    'modified_date': datetime.fromtimestamp(os.path.getmtime(image_path)).isoformat()
                }
                return info
        except Exception as e:
            console.print(f"[red]Error getting basic info: {str(e)}[/]")
            return {}

    def _extract_exif(self, image_path: str) -> Dict:
        """Extract EXIF metadata from image."""
        try:
            exif_data = {}
            with Image.open(image_path) as img:
                if hasattr(img, '_getexif') and img._getexif() is not None:
                    for tag_id in img._getexif():
                        tag = TAGS.get(tag_id, tag_id)
                        data = img._getexif().get(tag_id)
                        if isinstance(data, bytes):
                            data = data.decode()
                        exif_data[tag] = data
            return exif_data
        except Exception as e:
            console.print(f"[red]Error extracting EXIF: {str(e)}[/]")
            return {}

    def _analyze_geolocation(self, image_path: str) -> Dict:
        """Analyze geolocation data from image."""
        try:
            geolocation = {}
            exif_data = self._extract_exif(image_path)
            
            # Extract GPS coordinates if available
            if 'GPSInfo' in exif_data:
                gps_info = exif_data['GPSInfo']
                if isinstance(gps_info, dict):
                    lat = self._convert_to_degrees(gps_info.get(2, []))
                    lon = self._convert_to_degrees(gps_info.get(4, []))
                    
                    if lat and lon:
                        geolocation['coordinates'] = {
                            'latitude': lat,
                            'longitude': lon
                        }
                        
                        # Try to get location name
                        try:
                            location = self.geolocator.reverse(f"{lat}, {lon}")
                            if location:
                                geolocation['location'] = location.address
                        except GeocoderTimedOut:
                            pass
            
            return geolocation
        except Exception as e:
            console.print(f"[red]Error analyzing geolocation: {str(e)}[/]")
            return {}

    def _check_hidden_content(self, image_path: str) -> Dict:
        """Check for hidden content in image."""
        try:
            hidden_content = {
                'lsb_steganography': self._check_lsb_steganography(image_path),
                'metadata_steganography': self._check_metadata_steganography(image_path),
                'visual_analysis': self._analyze_visual_anomalies(image_path)
            }
            return hidden_content
        except Exception as e:
            console.print(f"[red]Error checking hidden content: {str(e)}[/]")
            return {}

    def _find_similar_images(self, image_path: str) -> List[Dict]:
        """Find similar images using reverse image search."""
        try:
            # Generate image hash
            img_hash = self._generate_image_hash(image_path)
            
            # TODO: Implement reverse image search using various APIs
            # This is a placeholder for the actual implementation
            similar_images = []
            
            return similar_images
        except Exception as e:
            console.print(f"[red]Error finding similar images: {str(e)}[/]")
            return []

    def _generate_image_hash(self, image_path: str) -> Dict:
        """Generate various image hashes for comparison."""
        try:
            with Image.open(image_path) as img:
                hashes = {
                    'average_hash': str(average_hash(img)),
                    'perceptual_hash': str(phash(img)),
                    'difference_hash': str(dhash(img)),
                    'wavelet_hash': str(whash(img))
                }
                return hashes
        except Exception as e:
            console.print(f"[red]Error generating image hash: {str(e)}[/]")
            return {}

    def _convert_to_degrees(self, value: List) -> float:
        """Convert GPS coordinates to degrees."""
        try:
            d = float(value[0])
            m = float(value[1])
            s = float(value[2])
            return d + (m / 60.0) + (s / 3600.0)
        except:
            return None

    def _check_lsb_steganography(self, image_path: str) -> Dict:
        """Check for LSB steganography."""
        try:
            result = {
                'detected': False,
                'message': None
            }
            
            # Try to extract hidden message
            try:
                message = lsb.reveal(image_path)
                if message:
                    result['detected'] = True
                    result['message'] = message
            except:
                pass
            
            return result
        except Exception as e:
            console.print(f"[red]Error checking LSB steganography: {str(e)}[/]")
            return {'detected': False, 'message': None}

    def _check_metadata_steganography(self, image_path: str) -> Dict:
        """Check for metadata steganography."""
        try:
            result = {
                'detected': False,
                'suspicious_fields': []
            }
            
            # Check for suspicious metadata fields
            exif_data = self._extract_exif(image_path)
            for field, value in exif_data.items():
                if isinstance(value, str) and len(value) > 100:
                    result['suspicious_fields'].append(field)
            
            if result['suspicious_fields']:
                result['detected'] = True
            
            return result
        except Exception as e:
            console.print(f"[red]Error checking metadata steganography: {str(e)}[/]")
            return {'detected': False, 'suspicious_fields': []}

    def _analyze_visual_anomalies(self, image_path: str) -> Dict:
        """Analyze image for visual anomalies."""
        try:
            result = {
                'anomalies_detected': False,
                'anomaly_details': []
            }
            
            # Load image with OpenCV
            img = cv2.imread(image_path)
            if img is None:
                return result
            
            # Convert to grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Check for noise patterns
            noise = cv2.Laplacian(gray, cv2.CV_64F).var()
            if noise > 1000:  # Threshold for noise detection
                result['anomalies_detected'] = True
                result['anomaly_details'].append({
                    'type': 'high_noise',
                    'value': noise
                })
            
            # Check for unusual color distributions
            hist = cv2.calcHist([img], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            hist = cv2.normalize(hist, hist).flatten()
            
            # Check for unusual peaks in histogram
            if np.max(hist) > 0.5:  # Threshold for unusual distribution
                result['anomalies_detected'] = True
                result['anomaly_details'].append({
                    'type': 'unusual_color_distribution',
                    'value': float(np.max(hist))
                })
            
            return result
        except Exception as e:
            console.print(f"[red]Error analyzing visual anomalies: {str(e)}[/]")
            return {'anomalies_detected': False, 'anomaly_details': []}

    def display_image_analysis(self, analysis: Dict) -> None:
        """Display image analysis results in a formatted table."""
        table = Table(title="Image Analysis Results")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in analysis.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            table.add_row(str(key), str(value))
        
        console.print(table) 