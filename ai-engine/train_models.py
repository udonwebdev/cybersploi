"""
Model Training Pipeline
Generates synthetic training data and trains all models
"""

import json
import logging
from typing import List, Dict
from datetime import datetime
from pathlib import Path

from src.models import (
    VulnerabilityClassifier,
    RiskScoringModel,
    ExploitabilityPredictor,
    initialize_models
)
from src.model_evolution import (
    ModelRegistry,
    ModelPerformanceMonitor,
    initialize_evolution_engine,
    get_evolution_engine
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def generate_training_data() -> List[Dict]:
    """Generate synthetic training data for models"""
    logger.info("Generating training data...")
    
    vulnerability_types = {
        'sqli': {
            'titles': [
                'SQL Injection in Login Form',
                'Blind SQL Injection in User API',
                'Time-based SQL Injection',
                'SQL Injection in Search',
                'Union-based SQL Injection'
            ],
            'descriptions': [
                'Attacker can inject SQL commands through unvalidated user input',
                'Database queries not properly sanitized',
                'Unsanitized search parameters allow SQL injection',
                'Direct query concatenation with user input',
                'No input validation on database operations'
            ],
            'severity': 'critical'
        },
        'xss': {
            'titles': [
                'Stored XSS in Comments',
                'Reflected XSS in URL Parameter',
                'DOM-based XSS',
                'XSS in User Profile',
                'Persistent XSS in Forum'
            ],
            'descriptions': [
                'User input reflected in response without encoding',
                'JavaScript code injection via URL parameters',
                'DOM manipulation allows script injection',
                'Profile content not properly escaped',
                'Comments stored and executed in browser'
            ],
            'severity': 'high'
        },
        'rce': {
            'titles': [
                'Remote Code Execution via File Upload',
                'RCE in Template Engine',
                'Deserialization RCE',
                'Command Injection',
                'Code Execution via YAML'
            ],
            'descriptions': [
                'Uploaded files can execute arbitrary code',
                'Template injection allows code execution',
                'Unsafe deserialization leads to RCE',
                'OS command construction from user input',
                'YAML deserialization vulnerability'
            ],
            'severity': 'critical'
        },
        'auth': {
            'titles': [
                'Broken Authentication',
                'Weak Password Policy',
                'Default Credentials',
                'Session Fixation',
                'Credential Enumeration'
            ],
            'descriptions': [
                'Authentication mechanism can be bypassed',
                'Password requirements too weak',
                'Application has known default accounts',
                'Session ID not regenerated after login',
                'User enumeration via response timing'
            ],
            'severity': 'high'
        },
        'crypto': {
            'titles': [
                'Weak Cryptographic Implementation',
                'Hardcoded Encryption Keys',
                'Broken Cipher',
                'Inadequate Random Number Generation',
                'SSL/TLS Certificate Validation'
            ],
            'descriptions': [
                'Uses outdated or weak encryption algorithms',
                'Encryption keys stored in code',
                'Custom crypto implementation with flaws',
                'Predictable random number generation',
                'Does not validate SSL certificates properly'
            ],
            'severity': 'high'
        },
        'misc': {
            'titles': [
                'Information Disclosure',
                'Insufficient Logging',
                'Configuration Issue',
                'Race Condition',
                'Logic Flaw'
            ],
            'descriptions': [
                'Sensitive information exposed in responses',
                'Security events not properly logged',
                'Insecure configuration settings',
                'Concurrent access leads to inconsistent state',
                'Business logic can be bypassed'
            ],
            'severity': 'medium'
        }
    }
    
    training_data = []
    
    for vuln_type, templates in vulnerability_types.items():
        for i in range(10):  # 10 samples per type
            training_data.append({
                'title': templates['titles'][i % len(templates['titles'])],
                'description': templates['descriptions'][i % len(templates['descriptions'])],
                'type': vuln_type,
                'severity': templates['severity'],
                'cvss': 5.0 + (len(training_data) % 10) * 0.5,
                'attack_vector': 'NETWORK' if i % 2 == 0 else 'ADJACENT',
                'exploitability': 0.3 + (i % 5) * 0.2,
                'impact_score': 0.5 + (i % 5) * 0.1,
                'requires_auth': i % 3 == 0,
                'user_interaction': i % 4 == 0,
                'complexity': 'LOW' if i % 2 == 0 else 'HIGH',
                'data_breach_risk': 0.3 + (i % 7) * 0.1,
                'remediation': f'Apply security patch or implement proper {vuln_type} protection'
            })
    
    logger.info(f"Generated {len(training_data)} training samples")
    return training_data


def train_all_models(training_data: List[Dict]):
    """Train all ML models"""
    logger.info("=" * 60)
    logger.info("TRAINING ALL MODELS")
    logger.info("=" * 60)
    
    registry = ModelRegistry()
    
    # Train Vulnerability Classifier
    logger.info("\n📊 Training Vulnerability Classifier...")
    classifier = VulnerabilityClassifier()
    classifier_metrics = classifier.train(training_data)
    classifier.save()
    registry.register_model(classifier.model_id, 'vulnerability_classifier', classifier_metrics)
    logger.info(f"✓ Classifier trained - Accuracy: {classifier_metrics['accuracy']:.3f}")
    
    # Train Risk Scorer
    logger.info("\n🎯 Training Risk Scoring Model...")
    risk_scorer = RiskScoringModel()
    risk_labels = [v['severity'] for v in training_data]
    risk_metrics = risk_scorer.train(training_data, risk_labels)
    registry.register_model(risk_scorer.model_id, 'risk_scorer', risk_metrics)
    logger.info(f"✓ Risk Scorer trained - Accuracy: {risk_metrics['accuracy']:.3f}")
    
    # Train Exploitability Predictor
    logger.info("\n⚡ Training Exploitability Predictor...")
    predictor = ExploitabilityPredictor()
    exploit_labels = [v['exploitability'] for v in training_data]
    exploit_metrics = predictor.train(training_data, exploit_labels, epochs=50)
    registry.register_model(predictor.model_id, 'exploitability_predictor', exploit_metrics)
    logger.info(f"✓ Exploitability Predictor trained - AUC: {exploit_metrics.get('auc', 0):.3f}")
    
    # Log training events
    monitor = ModelPerformanceMonitor()
    monitor.log_performance(classifier.model_id, 'vulnerability_classifier', classifier_metrics)
    monitor.log_performance(risk_scorer.model_id, 'risk_scorer', risk_metrics)
    monitor.log_performance(predictor.model_id, 'exploitability_predictor', exploit_metrics)
    
    logger.info("\n" + "=" * 60)
    logger.info("✓ ALL MODELS TRAINED SUCCESSFULLY")
    logger.info("=" * 60)
    
    return {
        'classifier': classifier_metrics,
        'risk_scorer': risk_metrics,
        'exploitability_predictor': exploit_metrics
    }


def test_models(training_data: List[Dict]):
    """Test trained models"""
    logger.info("\n" + "=" * 60)
    logger.info("TESTING MODELS")
    logger.info("=" * 60)
    
    # Select 5 random samples for testing
    test_samples = training_data[:5]
    
    initialize_models()
    from src.models import get_models
    models = get_models()
    
    # Test classifier
    logger.info("\n🔍 Testing Vulnerability Classifier...")
    classifier_predictions = models['vulnerability_classifier'].predict(test_samples)
    for i, pred in enumerate(classifier_predictions):
        logger.info(f"  Sample {i+1}: {pred['type']} (confidence: {pred['confidence']:.2f})")
    
    # Test risk scorer
    logger.info("\n🎯 Testing Risk Scorer...")
    risk_predictions = models['risk_scorer'].predict(test_samples)
    for i, pred in enumerate(risk_predictions):
        logger.info(f"  Sample {i+1}: {pred['risk_level']} (score: {pred['score']:.2f})")
    
    # Test exploitability predictor
    logger.info("\n⚡ Testing Exploitability Predictor...")
    exploit_predictions = models['exploitability_predictor'].predict(test_samples)
    for i, pred in enumerate(exploit_predictions):
        logger.info(f"  Sample {i+1}: {pred['level']} (score: {pred['exploitability_score']:.2f})")
    
    logger.info("\n✓ ALL MODELS TESTED")


def main():
    """Main training pipeline"""
    logger.info("🚀 Starting Model Training Pipeline...")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    
    # Generate training data
    training_data = generate_training_data()
    
    # Train all models
    results = train_all_models(training_data)
    
    # Test models
    test_models(training_data)
    
    # Initialize evolution engine
    initialize_evolution_engine()
    evolution_engine = get_evolution_engine()
    stats = evolution_engine.get_model_stats()
    
    logger.info("\n" + "=" * 60)
    logger.info("MODEL REGISTRY")
    logger.info("=" * 60)
    logger.info(json.dumps(stats['registry'], indent=2))
    
    logger.info("\n✅ TRAINING PIPELINE COMPLETE")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
