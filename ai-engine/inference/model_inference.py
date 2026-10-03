"""
Model inference and deployment module.
Provides endpoints for using trained models in FastAPI service.
"""

import torch
import numpy as np
import pickle
from pathlib import Path
from typing import Dict, List, Optional


class VulnerabilityInferenceEngine:
    """Inference engine for vulnerability classifier."""
    
    def __init__(self, model_path: str, feature_names: List[str]):
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.model_path = model_path
        self.feature_names = feature_names
        
        # Import model class
        from training.model_trainer import VulnerabilityClassifier
        
        self.model = VulnerabilityClassifier(input_size=len(feature_names), num_classes=5)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        
        self.severity_labels = ["info", "low", "medium", "high", "critical"]
    
    def predict(self, features: Dict[str, float]) -> Dict:
        """Predict vulnerability severity."""
        # Extract features in correct order
        feature_vector = np.array([
            features.get(name, 0.0) for name in self.feature_names
        ]).reshape(1, -1)
        
        feature_tensor = torch.FloatTensor(feature_vector).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(feature_tensor)
            probabilities = torch.softmax(outputs, dim=1)[0].cpu().numpy()
            predicted_class = np.argmax(probabilities)
        
        return {
            "predicted_severity": self.severity_labels[predicted_class],
            "predicted_class": int(predicted_class),
            "confidence": float(probabilities[predicted_class]),
            "probabilities": {
                label: float(prob)
                for label, prob in zip(self.severity_labels, probabilities)
            }
        }


class MalwareInferenceEngine:
    """Inference engine for malware detector."""
    
    def __init__(self, model_path: str, feature_names: List[str]):
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.model_path = model_path
        self.feature_names = feature_names
        
        # Import model class
        from training.model_trainer import MalwareDetector
        
        self.model = MalwareDetector(input_size=len(feature_names), num_classes=5)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        
        self.threat_levels = ["clean", "low", "medium", "high", "critical"]
    
    def predict(self, features: Dict[str, float]) -> Dict:
        """Predict malware threat level."""
        # Extract features in correct order
        feature_vector = np.array([
            features.get(name, 0.0) for name in self.feature_names
        ]).reshape(1, -1)
        
        feature_tensor = torch.FloatTensor(feature_vector).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(feature_tensor)
            probabilities = torch.softmax(outputs, dim=1)[0].cpu().numpy()
            predicted_class = np.argmax(probabilities)
        
        return {
            "predicted_threat_level": self.threat_levels[predicted_class],
            "predicted_class": int(predicted_class),
            "confidence": float(probabilities[predicted_class]),
            "is_malicious": 1 if predicted_class > 0 else 0,
            "probabilities": {
                level: float(prob)
                for level, prob in zip(self.threat_levels, probabilities)
            }
        }


class ThreatIntelInferenceEngine:
    """Inference engine for threat risk scorer."""
    
    def __init__(self, model_path: str, feature_names: List[str]):
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.model_path = model_path
        self.feature_names = feature_names
        
        # Import model class
        from training.model_trainer import ThreatIntelRiskScorer
        
        self.model = ThreatIntelRiskScorer(input_size=len(feature_names), num_classes=4)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        
        self.threat_levels = ["low", "medium", "high", "critical"]
    
    def predict(self, features: Dict[str, float]) -> Dict:
        """Predict threat risk level."""
        # Extract features in correct order
        feature_vector = np.array([
            features.get(name, 0.0) for name in self.feature_names
        ]).reshape(1, -1)
        
        feature_tensor = torch.FloatTensor(feature_vector).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(feature_tensor)
            probabilities = torch.softmax(outputs, dim=1)[0].cpu().numpy()
            predicted_class = np.argmax(probabilities)
        
        return {
            "predicted_risk_level": self.threat_levels[predicted_class],
            "predicted_class": int(predicted_class),
            "confidence": float(probabilities[predicted_class]),
            "risk_score": float(predicted_class + 1) / 4 * 100,  # Scale to 0-100
            "probabilities": {
                level: float(prob)
                for level, prob in zip(self.threat_levels, probabilities)
            }
        }


class ModelRegistry:
    """Central registry for all inference engines."""
    
    def __init__(self, models_dir: str = "./trained_models", data_dir: str = "./training_data"):
        self.models_dir = Path(models_dir)
        self.data_dir = Path(data_dir)
        self.engines = {}
        
        self._load_feature_names()
        self._initialize_engines()
    
    def _load_feature_names(self):
        """Load feature names from training data."""
        self.feature_names = {}
        
        with open(self.data_dir / "vulnerability_training_data.pkl", 'rb') as f:
            data = pickle.load(f)
            self.feature_names['vulnerability'] = data['feature_names']
        
        with open(self.data_dir / "malware_training_data.pkl", 'rb') as f:
            data = pickle.load(f)
            self.feature_names['malware'] = data['feature_names']
        
        with open(self.data_dir / "threat_intel_training_data.pkl", 'rb') as f:
            data = pickle.load(f)
            self.feature_names['threat_intel'] = data['feature_names']
    
    def _initialize_engines(self):
        """Initialize all inference engines."""
        self.engines['vulnerability'] = VulnerabilityInferenceEngine(
            model_path=str(self.models_dir / "vulnerability_classifier.pth"),
            feature_names=self.feature_names['vulnerability']
        )
        
        self.engines['malware'] = MalwareInferenceEngine(
            model_path=str(self.models_dir / "malware_detector.pth"),
            feature_names=self.feature_names['malware']
        )
        
        self.engines['threat_intel'] = ThreatIntelInferenceEngine(
            model_path=str(self.models_dir / "threat_risk_scorer.pth"),
            feature_names=self.feature_names['threat_intel']
        )
    
    def predict_vulnerability(self, features: Dict[str, float]) -> Dict:
        """Predict vulnerability severity."""
        return self.engines['vulnerability'].predict(features)
    
    def predict_malware(self, features: Dict[str, float]) -> Dict:
        """Predict malware threat level."""
        return self.engines['malware'].predict(features)
    
    def predict_threat(self, features: Dict[str, float]) -> Dict:
        """Predict threat risk level."""
        return self.engines['threat_intel'].predict(features)


# Global registry instance
_model_registry: Optional[ModelRegistry] = None


def get_model_registry() -> ModelRegistry:
    """Get global model registry (lazy initialization)."""
    global _model_registry
    if _model_registry is None:
        _model_registry = ModelRegistry()
    return _model_registry
