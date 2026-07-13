"""
Configuration for ML-based vulnerability detection
"""
import os
from pathlib import Path


class MLConfig:
    """Configuration class for ML detection module"""
    
    # Model settings
    DEFAULT_MODEL_NAME = "microsoft/codebert-base"
    MAX_SEQUENCE_LENGTH = 512
    
    # Inference settings
    CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence to report a finding
    BATCH_SIZE = 8
    
    # Supported vulnerability types for ML detection
    SUPPORTED_VULN_TYPES = [
        "SQL Injection",
        "XSS",
        "Path Traversal", 
        "Command Injection",
        "Insecure Deserialization",
        "Hardcoded Credentials",
        "SSRF",
        "XXE"
    ]
    
    # CWE mappings for ML-detected vulnerabilities
    CWE_MAPPINGS = {
        "SQL Injection": "CWE-89",
        "XSS": "CWE-79",
        "Path Traversal": "CWE-22",
        "Command Injection": "CWE-78",
        "Insecure Deserialization": "CWE-502",
        "Hardcoded Credentials": "CWE-798",
        "SSRF": "CWE-918",
        "XXE": "CWE-611"
    }
    
    # Severity mappings
    SEVERITY_MAPPINGS = {
        "SQL Injection": "ERROR",
        "XSS": "WARN",
        "Path Traversal": "ERROR",
        "Command Injection": "ERROR",
        "Insecure Deserialization": "ERROR",
        "Hardcoded Credentials": "WARN",
        "SSRF": "WARN",
        "XXE": "ERROR"
    }
    
    # Model cache directory
    @staticmethod
    def get_model_cache_dir():
        cache_dir = os.getenv("ML_MODEL_CACHE", str(Path.home() / ".vulngraph" / "models"))
        Path(cache_dir).mkdir(parents=True, exist_ok=True)
        return cache_dir
    
    # Check if ML is enabled
    @staticmethod
    def is_ml_enabled():
        return os.getenv("ML_ENABLED", "false").lower() in ("true", "1", "yes")
    
    # Check if GPU is available
    @staticmethod
    def use_gpu():
        return os.getenv("ML_USE_GPU", "auto").lower() in ("true", "1", "yes", "auto")
