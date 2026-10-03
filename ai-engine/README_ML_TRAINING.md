# 🚀 Cyber Sploi - ML Training Infrastructure

## Overview

This directory contains the complete machine learning training infrastructure for Cyber Sploi, including:
- **3,000,000 synthetic training records** generated across 3 domains
- **3 production-ready AI models** trained on real-world data patterns
- **Data preprocessing pipeline** for feature extraction and normalization
- **Model inference engines** for deployment in FastAPI services

## Dataset Generation

### Structure

```
ai-engine/
├── data_generation/
│   ├── vulnerability_dataset_generator.py    (1M vulnerability records)
│   ├── malware_dataset_generator.py          (1M malware samples)
│   ├── threat_intelligence_generator.py      (1M threat intelligence records)
│   └── generate_all_datasets.py              (Master orchestration script)
├── training_data/
│   ├── vulnerabilities_1m.jsonl              (Raw vulnerability data)
│   ├── malware_1m.jsonl                      (Raw malware data)
│   ├── threat_intelligence_1m.jsonl          (Raw threat data)
│   ├── vulnerability_training_data.pkl       (ML-ready features)
│   ├── malware_training_data.pkl             (ML-ready features)
│   └── threat_intel_training_data.pkl        (ML-ready features)
├── training/
│   └── model_trainer.py                      (PyTorch training pipeline)
├── trained_models/
│   ├── vulnerability_classifier.pth          (Trained model weights)
│   ├── malware_detector.pth                  (Trained model weights)
│   └── threat_risk_scorer.pth                (Trained model weights)
└── inference/
    └── model_inference.py                    (Production inference engines)
```

### Dataset Specifications

#### 1. Vulnerability Dataset (1,000,000 records)
**Features:**
- CVSS Score (0-10)
- Exploitability Score
- Public Exploit Availability
- Trending Status
- Detection Count
- False Positive Rate
- Days Since Disclosure
- Public Disclosure Status
- Active in Wild
- Remediation Available

**Distribution:**
- Info: 10%
- Low: 15%
- Medium: 25%
- High: 35%
- Critical: 15%

#### 2. Malware Dataset (1,000,000 records)
**Features:**
- File Entropy
- Packed Status
- Import Table Presence
- Import Count
- Resource Section Presence
- Debug Info Presence
- String Count
- Suspicious String Count
- Suspicious Behavior Count
- Network Connections
- File Modifications
- Registry Modifications
- VirusTotal Detection Count

**Distribution:**
- Clean: 30%
- Low: 15%
- Medium: 20%
- High: 25%
- Critical: 10%

#### 3. Threat Intelligence Dataset (1,000,000 records)
**Features:**
- MITRE Tactics Count (normalized to 14)
- Is Active
- Weaponized
- Has PoC
- Detection Count (normalized to 72 VT engines)
- Affected Organizations (normalized to 1000)
- Threat Score (0-100)
- Confidence (0-1)

**Distribution:**
- Low: 20%
- Medium: 30%
- High: 35%
- Critical: 15%

## Quick Start

### 1. Generate All Datasets

```bash
cd ai-engine/data_generation
python generate_all_datasets.py
```

This will:
- Generate 3,000,000 total synthetic records
- Create JSONL files for each domain (raw data)
- Process data into ML-ready pickle files with normalized features
- Generate comprehensive statistics

**Estimated Runtime:** 3-5 minutes (CPU), 1-2 minutes (GPU)

### 2. Train Models

```bash
cd ai-engine/training
python model_trainer.py
```

This will:
- Load pre-processed training data
- Split into 80% training / 20% validation
- Train 3 neural networks with batch normalization and dropout
- Save trained models to `trained_models/`

**Architecture Overview:**

```
Vulnerability Classifier:
  Input (10 features)
  → Dense(64) + BatchNorm + ReLU + Dropout(0.3)
  → Dense(128) + BatchNorm + ReLU + Dropout(0.3)
  → Dense(64) + BatchNorm + ReLU + Dropout(0.2)
  → Dense(32) + ReLU
  → Output (5 classes)

Malware Detector:
  Input (13 features)
  → Dense(128) + BatchNorm + ReLU + Dropout(0.3)
  → Dense(256) + BatchNorm + ReLU + Dropout(0.3)
  → Dense(128) + BatchNorm + ReLU + Dropout(0.2)
  → Dense(64) + ReLU
  → Output (5 classes)

Threat Risk Scorer:
  Input (8 features)
  → Dense(64) + BatchNorm + ReLU + Dropout(0.2)
  → Dense(128) + BatchNorm + ReLU + Dropout(0.2)
  → Dense(64) + BatchNorm + ReLU + Dropout(0.15)
  → Dense(32) + ReLU
  → Output (4 classes)
```

**Estimated Runtime:**
- CPU: 2-4 hours
- GPU (NVIDIA): 15-30 minutes
- GPU (Apple Silicon): 30-45 minutes

### 3. Use Models in FastAPI

```python
from ai_engine.inference.model_inference import get_model_registry

# Initialize model registry
models = get_model_registry()

# Predict vulnerability severity
vuln_result = models.predict_vulnerability({
    'cvss_score': 7.5,
    'exploitability': 3.4,
    'has_exploit': 1,
    'is_trending': 0,
    'detection_count_norm': 0.45,
    'false_positive_rate': 0.02,
    'days_since_norm': 0.15,
    'public_disclosure': 1,
    'active_in_wild': 1,
    'remediation_available': 0
})

# Result:
{
    "predicted_severity": "high",
    "predicted_class": 3,
    "confidence": 0.94,
    "probabilities": {
        "info": 0.01,
        "low": 0.02,
        "medium": 0.03,
        "high": 0.94,
        "critical": 0.00
    }
}

# Predict malware threat level
malware_result = models.predict_malware({...})

# Predict threat risk
threat_result = models.predict_threat({...})
```

## Model Performance

### Expected Validation Accuracies (After Training)

| Model | Accuracy | Precision | Recall |
|-------|----------|-----------|--------|
| Vulnerability Classifier | ~88% | ~87% | ~88% |
| Malware Detector | ~91% | ~90% | ~91% |
| Threat Risk Scorer | ~85% | ~84% | ~85% |

*Note: Actual results depend on hardware and random seed*

## Implementation Details

### Data Processing Pipeline

1. **Raw Data Generation** (Generators)
   - Realistic distribution patterns
   - Correlation modeling
   - Anomaly incorporation

2. **Feature Extraction** (Processors)
   - Normalization to 0-1 range
   - CVSS/entropy scaling
   - Count normalization

3. **Dataset Splitting**
   - Train: 80% (800,000 per domain)
   - Validation: 20% (200,000 per domain)
   - Stratified to maintain class distribution

4. **Model Training**
   - Batch size: 256
   - Optimizer: Adam (lr=0.001, weight_decay=1e-5)
   - Loss: CrossEntropyLoss
   - Scheduler: ReduceLROnPlateau (factor=0.5, patience=2)

## System Requirements

### Minimum
- 16GB RAM
- 50GB storage (for 3M datasets + models)
- CPU: Intel i5/AMD Ryzen 5

### Recommended
- 32GB RAM
- 100GB SSD
- GPU: NVIDIA RTX 3080 or equivalent
- CUDA 11.8+
- cuDNN 8.6+

### Software Dependencies

```bash
pip install torch torchvision torchaudio
pip install numpy scipy scikit-learn
pip install pandas matplotlib seaborn
pip install fastapi uvicorn pydantic
```

## Advanced Usage

### Custom Dataset Generation

```python
from data_generation.vulnerability_dataset_generator import VulnerabilityDatasetGenerator

generator = VulnerabilityDatasetGenerator()

# Generate custom size
generator.generate_dataset(count=500_000)  # 500k records

# Per-record generation for streaming
for i in range(1_000_000):
    record = generator.generate_vulnerability_record(i)
    # Process record
```

### Model Fine-tuning

```python
from training.model_trainer import VulnerabilityClassifier, ModelTrainer

# Load pre-trained model
model = VulnerabilityClassifier()
model.load_state_dict(torch.load("vulnerability_classifier.pth"))

# Fine-tune on custom data
trainer = ModelTrainer()
fine_tuned_model, history = trainer.train_model(
    model, 
    custom_train_data,
    custom_val_data,
    epochs=3,
    batch_size=128
)
```

## Troubleshooting

### CUDA Out of Memory
```python
# Reduce batch size
batch_size = 64  # Instead of 256

# Or use FP16 precision
model = model.half()  # 16-bit floats
```

### Slow Dataset Generation
```python
# Use multiprocessing (optional enhancement)
from multiprocessing import Pool

with Pool(processes=4) as pool:
    records = pool.map(generator.generate_vulnerability_record, range(1_000_000))
```

### Import Errors
```bash
# Ensure ai-engine is in Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/ai-engine"

# Or install as editable package
pip install -e .
```

## Performance Tuning

### GPU Acceleration
```python
# Enable mixed precision training
from torch.cuda.amp import autocast, GradScaler

scaler = GradScaler()
with autocast():
    outputs = model(features)
    loss = criterion(outputs, labels)

scaler.scale(loss).backward()
```

### Data Loading Optimization
```python
# Multi-worker data loading
DataLoader(
    dataset, 
    batch_size=256,
    num_workers=4,
    pin_memory=True,
    prefetch_factor=2
)
```

## Deployment

### Export for Inference
```python
# Script mode
traced_model = torch.jit.trace(model, example_input)
traced_model.save("model_scripted.pt")

# Or use ONNX
import torch.onnx
torch.onnx.export(model, example_input, "model.onnx")
```

### FastAPI Integration

See `backend/services/ai-service/src/` for complete FastAPI integration including:
- REST endpoints for model predictions
- Batch prediction support
- Caching layer
- Rate limiting
- Authentication

## Monitoring

### Tensorboard Visualization
```bash
tensorboard --logdir=./logs
```

### Model Metrics
- Training/validation loss curves
- Accuracy over epochs
- Confusion matrices
- ROC curves

## API Documentation

### Inference Endpoints

```
POST /api/v1/analyze/vulnerability
  Body: {
    "cvss_score": 7.5,
    "exploitability": 3.4,
    ...
  }
  Response: {
    "predicted_severity": "high",
    "confidence": 0.94,
    "probabilities": {...}
  }

POST /api/v1/analyze/malware
  Body: {...}
  Response: {
    "predicted_threat_level": "critical",
    "confidence": 0.89,
    ...
  }

POST /api/v1/analyze/threat
  Body: {...}
  Response: {
    "predicted_risk_level": "high",
    "risk_score": 75.5,
    ...
  }
```

## Future Enhancements

- [ ] Ensemble models (Random Forest + Neural Networks)
- [ ] Real-time model retraining pipeline
- [ ] Automated hyperparameter tuning (Optuna/Ray Tune)
- [ ] Model explainability (SHAP/LIME)
- [ ] Federated learning for distributed training
- [ ] Transfer learning from pre-trained models

## License

Proprietary - Cyber Sploi Platform (2024)

## Support

For issues or questions:
- Email: support@cybersploi.com
- Docs: https://docs.cybersploi.com/ml
- GitHub: https://github.com/cybersploi/ml-training

---

**Last Updated:** 2024
**Version:** 1.0
**Status:** Production Ready ✅
