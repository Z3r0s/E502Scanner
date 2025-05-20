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
import exifread
import folium
from folium.plugins import MarkerCluster
import webbrowser
import tempfile

console = Console()

class ImageIntelligence:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.geolocator = Nominatim(user_agent="E502OSINT")
        self.supported_formats = ['.jpg', '.jpeg', '.png', '.tiff', '.bmp']
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'perceptual': imagehash.average_hash,
            'difference': imagehash.dhash,
            'wavelet': imagehash.whash,
            'color': imagehash.colorhash
        }
        
    def analyze_image(self, image_path: str) -> Dict:
        """Perform comprehensive image analysis."""
        try:
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return {}

            console.print(f"[bold green]Analyzing image: {image_path}[/]")
            
            # Basic image info
            with Image.open(image_path) as img:
                basic_info = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size,
                    'width': img.width,
                    'height': img.height
                }

            # EXIF data
            exif_data = self._extract_exif(image_path)
            
            # Geolocation data
            geo_data = self._analyze_geolocation(image_path)
            
            # Steganography check
            stego_data = self._check_hidden_content(image_path)
            
            # Image hashes
            hash_data = self._generate_image_hash(image_path)
            
            return {
                'basic_info': basic_info,
                'exif': exif_data,
                'geolocation': geo_data,
                'steganography': stego_data,
                'hashes': hash_data
            }
        except Exception as e:
            console.print(f"[red]Error analyzing image: {str(e)}[/]")
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
            
            # Try exifread first
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f)
                for tag in tags.keys():
                    if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                        exif_data[tag] = str(tags[tag])

            # Try piexif for additional data
            try:
                exif_dict = piexif.load(image_path)
                for ifd in ("0th", "Exif", "GPS", "1st"):
                    for tag in exif_dict[ifd]:
                        try:
                            exif_data[piexif.TAGS[ifd][tag]["name"]] = exif_dict[ifd][tag]
                        except:
                            pass
            except:
                pass

            return exif_data
        except Exception as e:
            console.print(f"[red]Error extracting EXIF data: {str(e)}[/]")
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
        """Convert GPS coordinates to decimal degrees."""
        try:
            d = float(value[0])
            m = float(value[1])
            s = float(value[2])
            return d + (m / 60.0) + (s / 3600.0)
        except:
            return 0.0

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
        """Display image analysis results."""
        if not analysis:
            console.print("[red]No image analysis results available.[/]")
            return

        # Basic Information
        basic_table = Table(title="Basic Image Information")
        basic_table.add_column("Property", style="cyan")
        basic_table.add_column("Value", style="green")

        if 'basic_info' in analysis:
            basic = analysis['basic_info']
            basic_table.add_row("Format", basic.get('format', 'Unknown'))
            basic_table.add_row("Mode", basic.get('mode', 'Unknown'))
            basic_table.add_row("Size", f"{basic.get('width', 0)}x{basic.get('height', 0)}")

        console.print(basic_table)

        # EXIF Data
        if 'exif' in analysis and analysis['exif']:
            exif_table = Table(title="EXIF Metadata")
            exif_table.add_column("Tag", style="cyan")
            exif_table.add_column("Value", style="green")

            for tag, value in analysis['exif'].items():
                exif_table.add_row(tag, str(value))

            console.print(exif_table)

        # Geolocation Data
        if 'geolocation' in analysis:
            geo = analysis['geolocation']
            if geo.get('latitude') and geo.get('longitude'):
                geo_table = Table(title="Geolocation Data")
                geo_table.add_column("Property", style="cyan")
                geo_table.add_column("Value", style="green")

                geo_table.add_row("Latitude", f"{geo['latitude']:.6f}")
                geo_table.add_row("Longitude", f"{geo['longitude']:.6f}")
                if geo.get('altitude'):
                    geo_table.add_row("Altitude", f"{geo['altitude']} meters")
                if geo.get('timestamp'):
                    geo_table.add_row("Timestamp", geo['timestamp'])

                console.print(geo_table)

                # Create and display map
                self._create_map(geo['latitude'], geo['longitude'])

        # Steganography Analysis
        if 'steganography' in analysis:
            stego = analysis['steganography']
            stego_table = Table(title="Steganography Analysis")
            stego_table.add_column("Property", style="cyan")
            stego_table.add_column("Value", style="green")

            if 'lsb_analysis' in stego:
                lsb = stego['lsb_analysis']
                stego_table.add_row("LSB Entropy", f"{lsb.get('entropy', 0):.2f}")

            if 'noise_analysis' in stego:
                noise = stego['noise_analysis']
                stego_table.add_row("Noise Level", f"{noise.get('noise_level', 0):.2f}")
                stego_table.add_row("Unusual Patterns", 
                    "[red]Yes[/]" if noise.get('unusual_patterns') else "[green]No[/]")

            stego_table.add_row("Suspicious", 
                "[red]Yes[/]" if stego.get('suspicious') else "[green]No[/]")

            console.print(stego_table)

        # Image Hashes
        if 'hashes' in analysis:
            hash_table = Table(title="Image Hashes")
            hash_table.add_column("Algorithm", style="cyan")
            hash_table.add_column("Hash", style="green")

            for algo, hash_value in analysis['hashes'].items():
                hash_table.add_row(algo, hash_value)

            console.print(hash_table)

    def _create_map(self, lat: float, lon: float) -> None:
        """Create and display a map with the geolocation."""
        try:
            # Create map
            m = folium.Map(location=[lat, lon], zoom_start=13)
            
            # Add marker
            folium.Marker(
                [lat, lon],
                popup=f"Lat: {lat:.6f}, Lon: {lon:.6f}",
                icon=folium.Icon(color='red', icon='info-sign')
            ).add_to(m)
            
            # Save to temporary file and open in browser
            with tempfile.NamedTemporaryFile(delete=False, suffix='.html') as tmp:
                m.save(tmp.name)
                webbrowser.open('file://' + tmp.name)
                
        except Exception as e:
            console.print(f"[red]Error creating map: {str(e)}[/]")

    def extract_geo_data(self, image_path: str) -> Dict:
        """Extract geolocation data from image EXIF."""
        try:
            exif_data = self._extract_exif(image_path)
            geo_data = {}
            
            # Extract GPS coordinates
            if 'GPS GPSLatitude' in exif_data and 'GPS GPSLongitude' in exif_data:
                lat = self._convert_to_degrees(exif_data['GPS GPSLatitude'])
                lon = self._convert_to_degrees(exif_data['GPS GPSLongitude'])
                
                # Check for North/South and East/West
                if 'GPS GPSLatitudeRef' in exif_data and exif_data['GPS GPSLatitudeRef'] == 'S':
                    lat = -lat
                if 'GPS GPSLongitudeRef' in exif_data and exif_data['GPS GPSLongitudeRef'] == 'W':
                    lon = -lon
                
                geo_data['latitude'] = lat
                geo_data['longitude'] = lon
            
            # Extract altitude if available
            if 'GPS GPSAltitude' in exif_data:
                alt = float(exif_data['GPS GPSAltitude'])
                if 'GPS GPSAltitudeRef' in exif_data and exif_data['GPS GPSAltitudeRef'] == 1:
                    alt = -alt
                geo_data['altitude'] = alt
            
            # Extract timestamp if available
            if 'GPS GPSDateStamp' in exif_data and 'GPS GPSTimeStamp' in exif_data:
                date = exif_data['GPS GPSDateStamp']
                time = exif_data['GPS GPSTimeStamp']
                geo_data['timestamp'] = f"{date} {time}"
            
            return geo_data
            
        except Exception as e:
            console.print(f"[red]Error extracting geolocation data: {str(e)}[/]")
            return {}

    def check_steganography(self, image_path: str) -> Dict:
        """Check for potential steganography in image."""
        try:
            results = {
                'LSB': False,
                'Metadata': False,
                'File_Size': False,
                'Color_Anomalies': False
            }
            
            # Check file size
            file_size = os.path.getsize(image_path)
            img = Image.open(image_path)
            expected_size = img.size[0] * img.size[1] * 3  # RGB bytes
            results['File_Size'] = file_size > expected_size * 1.1  # 10% larger than expected
            
            # Check for LSB steganography
            pixels = img.load()
            lsb_count = 0
            total_pixels = 0
            
            for x in range(img.size[0]):
                for y in range(img.size[1]):
                    r, g, b = pixels[x, y]
                    if r & 1 or g & 1 or b & 1:
                        lsb_count += 1
                    total_pixels += 1
            
            results['LSB'] = (lsb_count / total_pixels) > 0.5  # More than 50% of pixels have LSB set
            
            # Check for metadata anomalies
            exif_data = self._extract_exif(image_path)
            results['Metadata'] = len(exif_data) > 20  # More than 20 EXIF tags
            
            # Check for color anomalies
            color_hist = img.histogram()
            results['Color_Anomalies'] = max(color_hist) > (sum(color_hist) / len(color_hist)) * 2
            
            return results
            
        except Exception as e:
            console.print(f"[red]Error checking steganography: {str(e)}[/]")
            return {} 