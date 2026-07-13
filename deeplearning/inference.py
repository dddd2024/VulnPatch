"""
Real Deep Learning Inference for Vulnerability Detection
Uses CodeBERT model for semantic code understanding
"""
import re
import logging
import time
from typing import List, Dict, Any, Optional

from .config import MLConfig
from .model_loader import get_model_loader

logger = logging.getLogger(__name__)


class MLInference:
    """
    Real ML-based inference engine using CodeBERT.
    Performs semantic analysis of code to detect vulnerabilities.
    """
    
    # Vulnerability patterns for rule-based fallback
    PATTERNS = {
        "SQL Injection": [
            r'execute\s*\([^)]*%s',
            r'execute\s*\([^)]*\.format\(',
            r'execute\s*\([^)]*\+[^;]+\)',
            r'cursor\.execute\s*\([^)]*f["\']',
            r'conn\.execute\s*\([^)]*f["\']',
        ],
        "XSS": [
            r'render_template_string',
            r'Markup\s*\([^)]*\)',
            r'|safe\s*}}',
            r'Response\s*\([^)]*\)',
        ],
        "Command Injection": [
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'exec\s*\([^)]*\)',
        ],
        "Hardcoded Credentials": [
            r'password\s*=\s*["\'][^"\']{4,}["\']',
            r'api_key\s*=\s*["\'][^"\']{10,}["\']',
            r'secret\s*=\s*["\'][^"\']{8,}["\']',
            r'token\s*=\s*["\'][^"\']{20,}["\']',
        ],
        "Path Traversal": [
            r'open\s*\([^)]*\+[^)]*\)',
            r'open\s*\([^)]*\.join\(',
            r'Path\s*\([^)]*\+[^)]*\)',
        ],
    }
    
    def __init__(self):
        self.model_loader = get_model_loader()
        self._ml_available = False
        self._tokenizer = None
        self._model = None
        self._device = None
        self._load_model()
    
    def _load_model(self):
        """Load the real CodeBERT model"""
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            
            logger.info("Loading CodeBERT model for vulnerability detection...")
            
            # Set device (GPU if available)
            self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Using device: {self._device}")
            
            if self._device.type == "cuda":
                logger.info(f"GPU: {torch.cuda.get_device_name(0)}")
                logger.info(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")
            
            # Load tokenizer and model
            model_name = MLConfig.DEFAULT_MODEL_NAME
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_name,
                cache_dir=MLConfig.get_model_cache_dir()
            )
            
            # Load model with optimizations for inference
            self._model = AutoModelForSequenceClassification.from_pretrained(
                model_name,
                num_labels=len(MLConfig.SUPPORTED_VULN_TYPES),
                cache_dir=MLConfig.get_model_cache_dir(),
                use_safetensors=False,  # Avoid safetensors format issues
                torch_dtype=torch.float16 if self._device.type == "cuda" else torch.float32
            )
            
            self._model.to(self._device)
            self._model.eval()  # Set to evaluation mode
            
            self._ml_available = True
            logger.info(f"Model loaded successfully on {self._device}")
            
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self._ml_available = False
    
    def is_ml_available(self) -> bool:
        """Check if real ML model is loaded"""
        return self._ml_available and self._model is not None
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get device information"""
        info = {
            "device": str(self._device) if self._device else "cpu",
            "ml_available": self._ml_available,
        }
        if self._device and self._device.type == "cuda":
            import torch
            info["gpu_name"] = torch.cuda.get_device_name(0)
            info["gpu_memory_total"] = f"{torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB"
            info["gpu_memory_allocated"] = f"{torch.cuda.memory_allocated(0) / 1024**3:.1f} GB"
        return info
    
    def detect_vulnerabilities(
        self, 
        code: str, 
        filename: str,
        existing_findings: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities using real deep learning model.
        Falls back to pattern matching if model unavailable.
        """
        start_time = time.time()
        findings = []
        
        # Track existing findings to avoid duplicates
        existing_keys = set()
        if existing_findings:
            for f in existing_findings:
                key = (f.get("type", ""), int(f.get("line", 0)))
                existing_keys.add(key)
        
        # Use real ML model if available
        if self.is_ml_available():
            ml_findings = self._detect_with_model(code, filename, existing_keys)
            findings.extend(ml_findings)
            logger.info(f"ML detection completed in {time.time() - start_time:.2f}s, found {len(ml_findings)} issues")
        else:
            # Use pattern-based fallback
            pattern_findings = self._detect_with_patterns(code, filename, existing_keys)
            findings.extend(pattern_findings)
            logger.info(f"Pattern detection completed, found {len(pattern_findings)} issues")
        
        return findings
    
    def _detect_with_model(
        self, 
        code: str, 
        filename: str,
        existing_keys: set
    ) -> List[Dict[str, Any]]:
        """
        Real deep learning inference using CodeBERT.
        Analyzes code semantics to detect vulnerabilities.
        """
        import torch
        findings = []
        lines = code.split("\n")
        
        # Process code in chunks (sliding window)
        window_size = 10  # lines
        stride = 5
        
        for start_line in range(0, len(lines), stride):
            end_line = min(start_line + window_size, len(lines))
            chunk = "\n".join(lines[start_line:end_line])
            
            if len(chunk.strip()) < 20:
                continue
            
            try:
                # Tokenize
                inputs = self._tokenizer(
                    chunk,
                    return_tensors="pt",
                    max_length=512,
                    truncation=True,
                    padding=True
                )
                
                # Move to device
                inputs = {k: v.to(self._device) for k, v in inputs.items()}
                
                # Inference
                with torch.no_grad():
                    outputs = self._model(**inputs)
                    probabilities = torch.softmax(outputs.logits, dim=-1)
                    predicted_class = torch.argmax(probabilities, dim=-1).item()
                    confidence = probabilities[0][predicted_class].item()
                
                # Map to vulnerability type (using first few types as demo)
                if predicted_class < len(MLConfig.SUPPORTED_VULN_TYPES) and confidence >= MLConfig.CONFIDENCE_THRESHOLD:
                    vuln_type = MLConfig.SUPPORTED_VULN_TYPES[predicted_class]
                    
                    # Find most likely vulnerable line in chunk
                    vuln_line = self._find_vulnerable_line(lines, start_line, end_line, vuln_type)
                    key = (vuln_type, vuln_line)
                    
                    if key not in existing_keys:
                        finding = self._create_finding(
                            vuln_type=vuln_type,
                            filename=filename,
                            line=vuln_line,
                            confidence=confidence,
                            source="ml",
                            device=str(self._device)
                        )
                        findings.append(finding)
                        
            except Exception as e:
                logger.warning(f"ML inference failed for chunk: {e}")
                continue
        
        return findings
    
    def _find_vulnerable_line(self, lines: List[str], start: int, end: int, vuln_type: str) -> int:
        """Find the most likely vulnerable line in a chunk"""
        keywords = {
            "SQL Injection": ["execute", "query", "SELECT", "INSERT", "UPDATE", "DELETE"],
            "XSS": ["render", "html", "template", "Markup"],
            "Command Injection": ["system", "popen", "subprocess", "exec"],
            "Hardcoded Credentials": ["password", "api_key", "secret", "token"],
            "Path Traversal": ["open", "read", "Path", "join"],
        }
        
        vuln_keywords = keywords.get(vuln_type, [])
        best_line = start + 1
        best_score = 0
        
        for i in range(start, min(end, len(lines))):
            line = lines[i].lower()
            score = sum(1 for kw in vuln_keywords if kw.lower() in line)
            if score > best_score:
                best_score = score
                best_line = i + 1
        
        return best_line
    
    def _detect_with_patterns(
        self, 
        code: str, 
        filename: str,
        existing_keys: set
    ) -> List[Dict[str, Any]]:
        """Pattern-based fallback detection"""
        findings = []
        lines = code.split("\n")
        
        for vuln_type, patterns in self.PATTERNS.items():
            for line_num, line in enumerate(lines, start=1):
                if line.strip().startswith("#"):
                    continue
                
                for pattern in patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            key = (vuln_type, line_num)
                            
                            if key in existing_keys:
                                continue
                            
                            confidence = self._estimate_confidence(pattern, line)
                            
                            finding = self._create_finding(
                                vuln_type=vuln_type,
                                filename=filename,
                                line=line_num,
                                confidence=confidence,
                                source="ml-fallback",
                                device="cpu"
                            )
                            findings.append(finding)
                            break
                    except re.error:
                        continue
        
        return findings
    
    def _estimate_confidence(self, pattern: str, line: str) -> float:
        """Estimate confidence based on pattern specificity"""
        base_confidence = 0.6
        
        if any(x in line for x in ["f\"", "f'", "format(", "%", "+"]):
            base_confidence += 0.15
        
        if any(x in line.lower() for x in ["execute", "system", "popen", "eval"]):
            base_confidence += 0.1
        
        return min(base_confidence, 0.95)
    
    def _create_finding(
        self,
        vuln_type: str,
        filename: str,
        line: int,
        confidence: float,
        source: str,
        device: str
    ) -> Dict[str, Any]:
        """Create a standardized vulnerability finding"""
        return {
            "type": vuln_type,
            "file": filename,
            "line": line,
            "severity": MLConfig.SEVERITY_MAPPINGS.get(vuln_type, "WARN"),
            "confidence": self._map_confidence(confidence),
            "cwe": MLConfig.CWE_MAPPINGS.get(vuln_type, "CWE-Other"),
            "engine": "ml" if source == "ml" else "ml-fallback",
            "engines": ["ml"] if source == "ml" else ["ml-fallback"],
            "ml_source": source,
            "ml_confidence": round(confidence, 3),
            "ml_device": device,
        }
    
    def _map_confidence(self, raw_confidence: float) -> str:
        """Map numerical confidence to categorical"""
        if raw_confidence >= 0.85:
            return "high"
        elif raw_confidence >= 0.65:
            return "medium"
        else:
            return "low"


# Global inference instance
_ml_inference: Optional[MLInference] = None


def get_ml_inference() -> MLInference:
    """Get the global ML inference instance"""
    global _ml_inference
    if _ml_inference is None:
        _ml_inference = MLInference()
    return _ml_inference
