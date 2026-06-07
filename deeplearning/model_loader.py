"""
Model loader for ML-based vulnerability detection
Handles loading and caching of pre-trained models
"""
import os
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from .config import MLConfig

logger = logging.getLogger(__name__)


class ModelLoader:
    """
    Singleton model loader that manages ML model lifecycle.
    Supports lazy loading and caching of models.
    """
    
    _instance: Optional["ModelLoader"] = None
    _model: Optional[Any] = None
    _tokenizer: Optional[Any] = None
    _is_loaded: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Skip re-initialization if already loaded
        if self._is_loaded:
            return
        self._is_loaded = True
    
    def _try_load_transformers(self) -> bool:
        """Check if transformers library is available"""
        try:
            import transformers
            return True
        except ImportError:
            return False
    
    def _try_load_torch(self) -> bool:
        """Check if PyTorch is available"""
        try:
            import torch
            return True
        except ImportError:
            return False
    
    def load_model(self, model_name: Optional[str] = None) -> bool:
        """
        Load the ML model for vulnerability detection.
        Returns True if successful, False otherwise.
        """
        if model_name is None:
            model_name = MLConfig.DEFAULT_MODEL_NAME
        
        # Check if transformers is available
        if not self._try_load_transformers():
            logger.warning("transformers library not available, ML detection will use fallback")
            return False
        
        # Check if torch is available
        if not self._try_load_torch():
            logger.warning("PyTorch not available, ML detection will use fallback")
            return False
        
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            from transformers import pipeline
            
            logger.info(f"Loading ML model: {model_name}")
            
            # Set device
            if MLConfig.use_gpu() and torch.cuda.is_available():
                device = 0
                logger.info("Using GPU for ML inference")
            else:
                device = -1
                logger.info("Using CPU for ML inference")
            
            # Load tokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_name,
                cache_dir=MLConfig.get_model_cache_dir()
            )
            
            # Create classification pipeline
            self._model = pipeline(
                "text-classification",
                model=model_name,
                tokenizer=self._tokenizer,
                device=device,
                cache_dir=MLConfig.get_model_cache_dir()
            )
            
            logger.info(f"ML model loaded successfully: {model_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self._model = None
            self._tokenizer = None
            return False
    
    def is_available(self) -> bool:
        """Check if ML model is available"""
        return self._model is not None
    
    def get_model(self):
        """Get the loaded model"""
        return self._model
    
    def get_tokenizer(self):
        """Get the loaded tokenizer"""
        return self._tokenizer


# Global model loader instance
_model_loader: Optional[ModelLoader] = None


def get_model_loader() -> ModelLoader:
    """Get the global model loader instance"""
    global _model_loader
    if _model_loader is None:
        _model_loader = ModelLoader()
    return _model_loader
