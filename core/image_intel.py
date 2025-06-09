"""
Image Intelligence Module for E502 OSINT Terminal
Provides advanced image analysis, EXIF extraction, geolocation, and forensics capabilities.
"""

import os
import logging
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import asyncio
import aiohttp
from PIL import Image, ExifTags
from PIL.ExifTags import TAGS
import piexif
from piexif import helper
import reverse_geocoder as rg
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import folium
from folium.plugins import MarkerCluster
import cv2
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from functools import wraps
import signal
from contextlib import contextmanager
import platform
import hashlib
import magic
import requests
from io import BytesIO
import base64
from dataclasses import dataclass
import pytesseract
from PIL.ExifTags import GPSTAGS
import pytz
from pathlib import Path
import shutil
import pandas as pd
import imagehash
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
from skimage import io, color, measure
from skimage.feature import local_binary_pattern
from skimage.transform import resize
from skimage.util import img_as_ubyte
import tensorflow as tf
from tensorflow.keras.applications import ResNet50
from tensorflow.keras.preprocessing import image
from tensorflow.keras.applications.resnet50 import preprocess_input, decode_predictions

logger = logging.getLogger("E502OSINT.ImageIntel")
console = Console()

@dataclass
class ImageMetadata:
    """Class for storing image metadata."""
    filename: str
    file_size: int
    dimensions: Tuple[int, int]
    created_date: Optional[datetime]
    modified_date: Optional[datetime]
    exif_data: Dict[str, Any]
    gps_data: Dict[str, Any]
    hash_values: Dict[str, str]
    mime_type: str
    format: str
    color_mode: str
    dpi: Optional[Tuple[int, int]]
    compression: Optional[str]
    camera_info: Dict[str, Any]
    software_info: Dict[str, Any]
    security_info: Dict[str, Any]

@dataclass
class ForensicsResult:
    """Class for storing forensics analysis results."""
    error_level_analysis: Dict[str, Any]
    noise_analysis: Dict[str, Any]
    copy_move_detection: Dict[str, Any]
    metadata_consistency: Dict[str, Any]
    steganography_detection: Dict[str, Any]
    compression_artifacts: Dict[str, Any]
    manipulation_indicators: List[str]
    confidence_score: float

class ImageIntelligence:
    def __init__(self):
        self.cache_dir = Path("cache/image_intel")
        self.output_dir = Path("output/image_intel")
        self.model_dir = Path("models/image_intel")
        self._ensure_dirs()
        self._load_models()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_models(self) -> None:
        """Load required models."""
        try:
            # Load ResNet50 for image classification
            self.classification_model = ResNet50(weights='imagenet')
            
            # Load other models as needed
            # self.manipulation_model = tf.keras.models.load_model(self.model_dir / "manipulation_detection.h5")
            # self.steganography_model = tf.keras.models.load_model(self.model_dir / "steganography_detection.h5")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """Perform comprehensive image analysis."""
        try:
            # Load image
            img = Image.open(image_path)
            
            # Extract metadata
            metadata = self._extract_metadata(img, image_path)
            
            # Perform forensics analysis
            forensics = self._perform_forensics(img)
            
            # Analyze content
            content_analysis = self._analyze_content(img)
            
            # Check for security issues
            security_issues = self._check_security_issues(metadata, forensics)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(metadata, forensics, security_issues)
            
            return {
                'metadata': asdict(metadata),
                'forensics': asdict(forensics),
                'content_analysis': content_analysis,
                'security_issues': security_issues,
                'recommendations': recommendations
            }
            
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}")
            return {'error': str(e)}
    
    def _extract_metadata(self, img: Image.Image, image_path: str) -> ImageMetadata:
        """Extract image metadata."""
        try:
            # Get basic file info
            file_stats = os.stat(image_path)
            
            # Extract EXIF data
            exif_data = {}
            if 'exif' in img.info:
                exif = piexif.load(img.info['exif'])
                for ifd in ('0th', 'Exif', 'GPS', '1st'):
                    for tag in exif[ifd]:
                        try:
                            tag_name = TAGS.get(tag, tag)
                            exif_data[tag_name] = exif[ifd][tag]
                        except:
                            continue
            
            # Extract GPS data
            gps_data = {}
            if 'GPSInfo' in exif_data:
                for tag in exif_data['GPSInfo']:
                    try:
                        tag_name = GPSTAGS.get(tag, tag)
                        gps_data[tag_name] = exif_data['GPSInfo'][tag]
                    except:
                        continue
            
            # Calculate hash values
            hash_values = {
                'md5': hashlib.md5(open(image_path, 'rb').read()).hexdigest(),
                'sha1': hashlib.sha1(open(image_path, 'rb').read()).hexdigest(),
                'sha256': hashlib.sha256(open(image_path, 'rb').read()).hexdigest(),
                'perceptual': str(imagehash.average_hash(img))
            }
            
            # Get camera and software info
            camera_info = {
                'make': exif_data.get('Make', 'Unknown'),
                'model': exif_data.get('Model', 'Unknown'),
                'software': exif_data.get('Software', 'Unknown'),
                'datetime': exif_data.get('DateTime', 'Unknown')
            }
            
            return ImageMetadata(
                filename=os.path.basename(image_path),
                file_size=file_stats.st_size,
                dimensions=img.size,
                created_date=datetime.fromtimestamp(file_stats.st_ctime),
                modified_date=datetime.fromtimestamp(file_stats.st_mtime),
                exif_data=exif_data,
                gps_data=gps_data,
                hash_values=hash_values,
                mime_type=magic.from_file(image_path, mime=True),
                format=img.format,
                color_mode=img.mode,
                dpi=img.info.get('dpi'),
                compression=img.info.get('compression'),
                camera_info=camera_info,
                software_info={
                    'software': exif_data.get('Software', 'Unknown'),
                    'processing_software': exif_data.get('ProcessingSoftware', 'Unknown')
                },
                security_info={
                    'is_encrypted': False,  # Add encryption detection
                    'has_watermark': False,  # Add watermark detection
                    'has_steganography': False  # Add steganography detection
                }
            )
            
        except Exception as e:
            logger.error(f"Error extracting metadata: {str(e)}")
            raise
    
    def _perform_forensics(self, img: Image.Image) -> ForensicsResult:
        """Perform forensics analysis."""
        try:
            # Convert to numpy array
            img_array = np.array(img)
            
            # Error Level Analysis
            ela_result = self._error_level_analysis(img_array)
            
            # Noise Analysis
            noise_result = self._noise_analysis(img_array)
            
            # Copy-Move Detection
            copy_move_result = self._detect_copy_move(img_array)
            
            # Metadata Consistency Check
            metadata_consistency = self._check_metadata_consistency(img)
            
            # Steganography Detection
            steganography_result = self._detect_steganography(img)
            
            # Compression Artifacts Analysis
            compression_result = self._analyze_compression_artifacts(img_array)
            
            # Combine results
            manipulation_indicators = []
            confidence_score = 0.0
            
            if ela_result['manipulation_detected']:
                manipulation_indicators.append("Error Level Analysis suggests manipulation")
                confidence_score += 0.3
            
            if copy_move_result['copy_move_detected']:
                manipulation_indicators.append("Copy-Move forgery detected")
                confidence_score += 0.3
            
            if not metadata_consistency['is_consistent']:
                manipulation_indicators.append("Metadata inconsistencies detected")
                confidence_score += 0.2
            
            if steganography_result['steganography_detected']:
                manipulation_indicators.append("Possible steganography detected")
                confidence_score += 0.2
            
            return ForensicsResult(
                error_level_analysis=ela_result,
                noise_analysis=noise_result,
                copy_move_detection=copy_move_result,
                metadata_consistency=metadata_consistency,
                steganography_detection=steganography_result,
                compression_artifacts=compression_result,
                manipulation_indicators=manipulation_indicators,
                confidence_score=min(confidence_score, 1.0)
            )
            
        except Exception as e:
            logger.error(f"Error performing forensics: {str(e)}")
            raise
    
    def _error_level_analysis(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Perform Error Level Analysis."""
        try:
            # Save image with specific quality
            temp_path = self.cache_dir / "temp_ela.jpg"
            Image.fromarray(img_array).save(temp_path, quality=90)
            
            # Load compressed image
            compressed = np.array(Image.open(temp_path))
            
            # Calculate difference
            diff = np.abs(img_array.astype(np.float32) - compressed.astype(np.float32))
            
            # Calculate statistics
            mean_diff = np.mean(diff)
            std_diff = np.std(diff)
            max_diff = np.max(diff)
            
            # Determine if manipulation is likely
            manipulation_detected = mean_diff > 5.0 or std_diff > 10.0
            
            return {
                'mean_difference': float(mean_diff),
                'std_difference': float(std_diff),
                'max_difference': float(max_diff),
                'manipulation_detected': bool(manipulation_detected)
            }
            
        except Exception as e:
            logger.error(f"Error in ELA: {str(e)}")
            return {
                'error': str(e),
                'manipulation_detected': False
            }
    
    def _noise_analysis(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Analyze image noise patterns."""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            
            # Calculate noise
            noise = cv2.fastNlMeansDenoising(gray)
            noise_pattern = gray - noise
            
            # Calculate statistics
            mean_noise = np.mean(noise_pattern)
            std_noise = np.std(noise_pattern)
            
            # Analyze noise distribution
            hist = np.histogram(noise_pattern, bins=50)
            
            return {
                'mean_noise': float(mean_noise),
                'std_noise': float(std_noise),
                'noise_distribution': hist[0].tolist(),
                'noise_bins': hist[1].tolist()
            }
            
        except Exception as e:
            logger.error(f"Error in noise analysis: {str(e)}")
            return {'error': str(e)}
    
    def _detect_copy_move(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Detect copy-move forgery."""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            
            # Extract features using LBP
            lbp = local_binary_pattern(gray, 8, 1, method='uniform')
            
            # Calculate LBP histogram
            hist = np.histogram(lbp, bins=59, range=(0, 59))
            
            # Analyze histogram for similarities
            similarities = []
            for i in range(len(hist[0])):
                if hist[0][i] > 2:  # Threshold for similarity
                    similarities.append(i)
            
            copy_move_detected = len(similarities) > 5
            
            return {
                'copy_move_detected': bool(copy_move_detected),
                'similarity_score': float(len(similarities) / 59),
                'similar_regions': len(similarities)
            }
            
        except Exception as e:
            logger.error(f"Error in copy-move detection: {str(e)}")
            return {
                'error': str(e),
                'copy_move_detected': False
            }
    
    def _check_metadata_consistency(self, img: Image.Image) -> Dict[str, Any]:
        """Check metadata consistency."""
        try:
            inconsistencies = []
            
            # Check EXIF data
            if 'exif' in img.info:
                exif = piexif.load(img.info['exif'])
                
                # Check date consistency
                if '0th' in exif and 306 in exif['0th']:  # DateTime
                    date_str = exif['0th'][306].decode('utf-8')
                    try:
                        exif_date = datetime.strptime(date_str, '%Y:%m:%d %H:%M:%S')
                        file_date = datetime.fromtimestamp(os.path.getmtime(img.filename))
                        if abs((exif_date - file_date).total_seconds()) > 3600:
                            inconsistencies.append("File modification time differs from EXIF date")
                    except:
                        inconsistencies.append("Invalid EXIF date format")
                
                # Check GPS data consistency
                if 'GPS' in exif:
                    gps_data = exif['GPS']
                    if 1 in gps_data and 2 in gps_data:  # Latitude and Longitude
                        try:
                            lat = self._convert_to_degrees(gps_data[1])
                            lon = self._convert_to_degrees(gps_data[2])
                            if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                                inconsistencies.append("Invalid GPS coordinates")
                        except:
                            inconsistencies.append("Invalid GPS data format")
            
            return {
                'is_consistent': len(inconsistencies) == 0,
                'inconsistencies': inconsistencies
            }
            
        except Exception as e:
            logger.error(f"Error checking metadata consistency: {str(e)}")
            return {
                'error': str(e),
                'is_consistent': False
            }
    
    def _detect_steganography(self, img: Image.Image) -> Dict[str, Any]:
        """Detect steganography."""
        try:
            # Convert to numpy array
            img_array = np.array(img)
            
            # Analyze LSB
            lsb_analysis = self._analyze_lsb(img_array)
            
            # Check for statistical anomalies
            statistical_analysis = self._analyze_statistics(img_array)
            
            # Combine results
            steganography_detected = (
                lsb_analysis['lsb_anomaly'] or
                statistical_analysis['statistical_anomaly']
            )
            
            return {
                'steganography_detected': bool(steganography_detected),
                'lsb_analysis': lsb_analysis,
                'statistical_analysis': statistical_analysis,
                'confidence_score': float(
                    lsb_analysis['confidence'] +
                    statistical_analysis['confidence']
                ) / 2
            }
            
        except Exception as e:
            logger.error(f"Error detecting steganography: {str(e)}")
            return {
                'error': str(e),
                'steganography_detected': False
            }
    
    def _analyze_compression_artifacts(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Analyze compression artifacts."""
        try:
            # Convert to YCrCb color space
            ycrcb = cv2.cvtColor(img_array, cv2.COLOR_RGB2YCrCb)
            
            # Analyze each channel
            artifacts = {}
            for i, channel in enumerate(['Y', 'Cr', 'Cb']):
                # Calculate DCT
                dct = cv2.dct(ycrcb[:,:,i].astype(np.float32))
                
                # Analyze DCT coefficients
                artifacts[channel] = {
                    'mean': float(np.mean(dct)),
                    'std': float(np.std(dct)),
                    'max': float(np.max(dct)),
                    'min': float(np.min(dct))
                }
            
            # Check for compression artifacts
            compression_detected = any(
                abs(artifacts[channel]['mean']) > 10 or
                artifacts[channel]['std'] > 20
                for channel in artifacts
            )
            
            return {
                'compression_detected': bool(compression_detected),
                'channel_artifacts': artifacts
            }
            
        except Exception as e:
            logger.error(f"Error analyzing compression artifacts: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_content(self, img: Image.Image) -> Dict[str, Any]:
        """Analyze image content."""
        try:
            # Prepare image for model
            img_array = np.array(img)
            img_array = cv2.resize(img_array, (224, 224))
            img_array = np.expand_dims(img_array, axis=0)
            img_array = preprocess_input(img_array)
            
            # Get predictions
            predictions = self.classification_model.predict(img_array)
            decoded_predictions = decode_predictions(predictions, top=5)[0]
            
            # Extract dominant colors
            img_array = np.array(img)
            pixels = img_array.reshape(-1, 3)
            from sklearn.cluster import KMeans
            kmeans = KMeans(n_clusters=5, random_state=42)
            kmeans.fit(pixels)
            colors = kmeans.cluster_centers_
            
            # Calculate color percentages
            labels = kmeans.labels_
            color_percentages = np.bincount(labels) / len(labels)
            
            return {
                'predictions': [
                    {
                        'label': label,
                        'confidence': float(confidence)
                    }
                    for _, label, confidence in decoded_predictions
                ],
                'dominant_colors': [
                    {
                        'color': color.tolist(),
                        'percentage': float(percentage)
                    }
                    for color, percentage in zip(colors, color_percentages)
                ]
            }
            
        except Exception as e:
            logger.error(f"Error analyzing content: {str(e)}")
            return {'error': str(e)}
    
    def _check_security_issues(self, metadata: ImageMetadata, forensics: ForensicsResult) -> List[str]:
        """Check for security issues."""
        issues = []
        
        # Check for GPS data
        if metadata.gps_data:
            issues.append("Image contains GPS location data")
        
        # Check for manipulation
        if forensics.manipulation_indicators:
            issues.append("Image shows signs of manipulation")
        
        # Check for steganography
        if forensics.steganography_detection['steganography_detected']:
            issues.append("Possible steganography detected")
        
        # Check for sensitive metadata
        sensitive_fields = ['Software', 'ProcessingSoftware', 'Copyright', 'Artist']
        for field in sensitive_fields:
            if field in metadata.exif_data:
                issues.append(f"Image contains {field} information")
        
        return issues
    
    def _generate_recommendations(self, metadata: ImageMetadata, forensics: ForensicsResult, security_issues: List[str]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Handle GPS data
        if "Image contains GPS location data" in security_issues:
            recommendations.append("Consider removing GPS data for privacy")
        
        # Handle manipulation
        if "Image shows signs of manipulation" in security_issues:
            recommendations.append("Verify image authenticity with source")
        
        # Handle steganography
        if "Possible steganography detected" in security_issues:
            recommendations.append("Investigate potential hidden content")
        
        # Handle sensitive metadata
        if any("contains" in issue for issue in security_issues):
            recommendations.append("Consider removing sensitive metadata")
        
        # General recommendations
        if forensics.confidence_score > 0.7:
            recommendations.append("High confidence of image manipulation")
        elif forensics.confidence_score > 0.3:
            recommendations.append("Possible image manipulation detected")
        
        return recommendations
    
    def _convert_to_degrees(self, value: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]) -> float:
        """Convert GPS coordinates to degrees."""
        d = float(value[0][0]) / float(value[0][1])
        m = float(value[1][0]) / float(value[1][1])
        s = float(value[2][0]) / float(value[2][1])
        return d + (m / 60.0) + (s / 3600.0)
    
    def _analyze_lsb(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Analyze Least Significant Bits."""
        try:
            # Extract LSB
            lsb = img_array & 1
            
            # Calculate LSB statistics
            lsb_mean = np.mean(lsb)
            lsb_std = np.std(lsb)
            
            # Check for LSB anomalies
            lsb_anomaly = abs(lsb_mean - 0.5) > 0.1 or lsb_std > 0.1
            
            return {
                'lsb_anomaly': bool(lsb_anomaly),
                'lsb_mean': float(lsb_mean),
                'lsb_std': float(lsb_std),
                'confidence': float(abs(lsb_mean - 0.5) * 2)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing LSB: {str(e)}")
            return {
                'error': str(e),
                'lsb_anomaly': False
            }
    
    def _analyze_statistics(self, img_array: np.ndarray) -> Dict[str, Any]:
        """Analyze image statistics."""
        try:
            # Calculate histogram
            hist = cv2.calcHist([img_array], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            hist = hist.flatten()
            
            # Calculate statistics
            hist_mean = np.mean(hist)
            hist_std = np.std(hist)
            
            # Check for statistical anomalies
            statistical_anomaly = hist_std > hist_mean * 2
            
            return {
                'statistical_anomaly': bool(statistical_anomaly),
                'histogram_mean': float(hist_mean),
                'histogram_std': float(hist_std),
                'confidence': float(min(hist_std / hist_mean, 1.0))
            }
            
        except Exception as e:
            logger.error(f"Error analyzing statistics: {str(e)}")
            return {
                'error': str(e),
                'statistical_anomaly': False
            }
    
    def display_analysis(self, analysis_results: Dict[str, Any]) -> None:
        """Display analysis results in a formatted way."""
        try:
            # Create main panel
            console.print(Panel.fit(
                f"[bold blue]Image Analysis Results[/]\n"
                f"Filename: {analysis_results['metadata']['filename']}\n"
                f"Size: {analysis_results['metadata']['file_size']} bytes\n"
                f"Dimensions: {analysis_results['metadata']['dimensions']}\n"
                f"Format: {analysis_results['metadata']['format']}\n"
                f"Color Mode: {analysis_results['metadata']['color_mode']}"
            ))
            
            # Display forensics results
            forensics = analysis_results['forensics']
            console.print("\n[bold red]Forensics Analysis[/]")
            console.print(f"Manipulation Confidence: {forensics['confidence_score']:.2%}")
            if forensics['manipulation_indicators']:
                console.print("\n[bold yellow]Manipulation Indicators:[/]")
                for indicator in forensics['manipulation_indicators']:
                    console.print(f"• {indicator}")
            
            # Display security issues
            if analysis_results['security_issues']:
                console.print("\n[bold red]Security Issues:[/]")
                for issue in analysis_results['security_issues']:
                    console.print(f"• {issue}")
            
            # Display recommendations
            if analysis_results['recommendations']:
                console.print("\n[bold green]Recommendations:[/]")
                for recommendation in analysis_results['recommendations']:
                    console.print(f"• {recommendation}")
            
            # Display content analysis
            content = analysis_results['content_analysis']
            if 'predictions' in content:
                console.print("\n[bold blue]Content Analysis:[/]")
                for pred in content['predictions']:
                    console.print(f"• {pred['label']}: {pred['confidence']:.2%}")
            
        except Exception as e:
            logger.error(f"Error displaying analysis: {str(e)}")
            console.print(f"[red]Error displaying analysis: {str(e)}[/]")

# Create global instance
image_intel = ImageIntelligence() 