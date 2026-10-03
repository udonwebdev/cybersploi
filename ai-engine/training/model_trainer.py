"""
PyTorch model training pipeline for Cyber Sploi AI system.
Trains vulnerability classifier, malware detector, and threat risk scorer.
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pickle
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict
import json


class VulnerabilityClassifier(nn.Module):
    """Neural network for vulnerability severity classification."""
    
    def __init__(self, input_size: int = 10, num_classes: int = 5):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            
            nn.Linear(32, num_classes)
        )
    
    def forward(self, x):
        return self.network(x)


class MalwareDetector(nn.Module):
    """Neural network for malware classification (binary + multi-class)."""
    
    def __init__(self, input_size: int = 13, num_classes: int = 5):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(128, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),
            
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            
            nn.Linear(64, num_classes)
        )
    
    def forward(self, x):
        return self.network(x)


class ThreatIntelRiskScorer(nn.Module):
    """Neural network for threat intelligence risk scoring."""
    
    def __init__(self, input_size: int = 8, num_classes: int = 4):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.2),
            
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.15),
            
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            
            nn.Linear(32, num_classes)
        )
    
    def forward(self, x):
        return self.network(x)


class ModelTrainer:
    """Trainer class for all models."""
    
    def __init__(self, device: str = None):
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.training_history = []
    
    def train_epoch(self, model, train_loader, criterion, optimizer):
        """Train for one epoch."""
        model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_idx, (features, labels) in enumerate(train_loader):
            features, labels = features.to(self.device), labels.to(self.device)
            
            optimizer.zero_grad()
            outputs = model(features)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
            
            if (batch_idx + 1) % 100 == 0:
                accuracy = 100 * correct / total
                print(f"      Batch {batch_idx + 1}: Loss={loss.item():.4f}, Acc={accuracy:.2f}%")
        
        avg_loss = total_loss / len(train_loader)
        accuracy = 100 * correct / total
        
        return avg_loss, accuracy
    
    def validate(self, model, val_loader, criterion):
        """Validate model."""
        model.eval()
        total_loss = 0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for features, labels in val_loader:
                features, labels = features.to(self.device), labels.to(self.device)
                outputs = model(features)
                loss = criterion(outputs, labels)
                
                total_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                total += labels.size(0)
                correct += (predicted == labels).sum().item()
        
        avg_loss = total_loss / len(val_loader)
        accuracy = 100 * correct / total
        
        return avg_loss, accuracy
    
    def train_model(self, model, train_data, val_data, epochs: int = 10, batch_size: int = 128):
        """Full training pipeline."""
        # Prepare data loaders
        train_features = torch.FloatTensor(train_data['features'])
        train_labels = torch.LongTensor(train_data['labels'])
        
        val_features = torch.FloatTensor(val_data['features'])
        val_labels = torch.LongTensor(val_data['labels'])
        
        train_dataset = TensorDataset(train_features, train_labels)
        val_dataset = TensorDataset(val_features, val_labels)
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=0)
        
        # Move model to device
        model = model.to(self.device)
        
        # Setup training
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)
        
        best_val_loss = float('inf')
        history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}
        
        for epoch in range(epochs):
            print(f"   Epoch {epoch + 1}/{epochs}")
            
            # Train
            train_loss, train_acc = self.train_epoch(model, train_loader, criterion, optimizer)
            history['train_loss'].append(train_loss)
            history['train_acc'].append(train_acc)
            
            # Validate
            val_loss, val_acc = self.validate(model, val_loader, criterion)
            history['val_loss'].append(val_loss)
            history['val_acc'].append(val_acc)
            
            scheduler.step(val_loss)
            
            print(f"      ✓ Train Loss={train_loss:.4f}, Acc={train_acc:.2f}%")
            print(f"      ✓ Val Loss={val_loss:.4f}, Acc={val_acc:.2f}%")
            
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                print(f"      ✅ Best model saved (Val Loss: {val_loss:.4f})")
        
        return model, history


def split_train_val(data: dict, train_ratio: float = 0.8):
    """Split data into training and validation sets."""
    n_samples = len(data['features'])
    train_size = int(n_samples * train_ratio)
    
    indices = np.random.permutation(n_samples)
    train_indices = indices[:train_size]
    val_indices = indices[train_size:]
    
    train_data = {
        'features': data['features'][train_indices],
        'labels': data['labels'][train_indices]
    }
    
    val_data = {
        'features': data['features'][val_indices],
        'labels': data['labels'][val_indices]
    }
    
    return train_data, val_data


def main():
    """Main training pipeline."""
    
    print("=" * 80)
    print("🚀 CYBER SPLOI - MODEL TRAINING PIPELINE")
    print("Training 3 AI models on 1M+ datasets")
    print("=" * 80)
    print()
    
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"🖥️  Device: {device}")
    if device == 'cuda':
        print(f"   GPU: {torch.cuda.get_device_name(0)}")
        print(f"   Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")
    print()
    
    data_dir = Path("./training_data")
    models_dir = Path("./trained_models")
    models_dir.mkdir(exist_ok=True)
    
    trainer = ModelTrainer(device=device)
    
    start_time = datetime.now()
    
    # TRAIN 1: Vulnerability Classifier
    print("🔴 MODEL 1: VULNERABILITY CLASSIFIER")
    print("-" * 80)
    print("Loading vulnerability training data...")
    
    with open(data_dir / "vulnerability_training_data.pkl", 'rb') as f:
        vuln_data = pickle.load(f)
    
    print(f"   Samples: {len(vuln_data['features']):,}")
    print(f"   Features: {len(vuln_data['feature_names'])}")
    print(f"   Classes: 5 (info, low, medium, high, critical)")
    
    vuln_train, vuln_val = split_train_val(vuln_data)
    vuln_model = VulnerabilityClassifier(input_size=len(vuln_data['feature_names']), num_classes=5)
    
    print("\nTraining Vulnerability Classifier...")
    vuln_model, vuln_history = trainer.train_model(
        vuln_model, vuln_train, vuln_val,
        epochs=5, batch_size=256
    )
    
    torch.save(vuln_model.state_dict(), models_dir / "vulnerability_classifier.pth")
    print("✅ Saved: vulnerability_classifier.pth\n")
    
    # TRAIN 2: Malware Detector
    print("🟠 MODEL 2: MALWARE DETECTOR")
    print("-" * 80)
    print("Loading malware training data...")
    
    with open(data_dir / "malware_training_data.pkl", 'rb') as f:
        malware_data = pickle.load(f)
    
    print(f"   Samples: {len(malware_data['features']):,}")
    print(f"   Features: {len(malware_data['feature_names'])}")
    print(f"   Classes: 5 (clean, low, medium, high, critical)")
    
    malware_train, malware_val = split_train_val(malware_data)
    malware_model = MalwareDetector(input_size=len(malware_data['feature_names']), num_classes=5)
    
    print("\nTraining Malware Detector...")
    malware_model, malware_history = trainer.train_model(
        malware_model, malware_train, malware_val,
        epochs=5, batch_size=256
    )
    
    torch.save(malware_model.state_dict(), models_dir / "malware_detector.pth")
    print("✅ Saved: malware_detector.pth\n")
    
    # TRAIN 3: Threat Risk Scorer
    print("🟡 MODEL 3: THREAT RISK SCORER")
    print("-" * 80)
    print("Loading threat intelligence training data...")
    
    with open(data_dir / "threat_intel_training_data.pkl", 'rb') as f:
        threat_data = pickle.load(f)
    
    print(f"   Samples: {len(threat_data['features']):,}")
    print(f"   Features: {len(threat_data['feature_names'])}")
    print(f"   Classes: 4 (low, medium, high, critical)")
    
    threat_train, threat_val = split_train_val(threat_data)
    threat_model = ThreatIntelRiskScorer(input_size=len(threat_data['feature_names']), num_classes=4)
    
    print("\nTraining Threat Risk Scorer...")
    threat_model, threat_history = trainer.train_model(
        threat_model, threat_train, threat_val,
        epochs=5, batch_size=256
    )
    
    torch.save(threat_model.state_dict(), models_dir / "threat_risk_scorer.pth")
    print("✅ Saved: threat_risk_scorer.pth\n")
    
    # Summary
    elapsed = datetime.now() - start_time
    
    print("=" * 80)
    print("✅ MODEL TRAINING COMPLETE")
    print("=" * 80)
    print(f"Total Training Time: {elapsed.total_seconds():.1f}s ({elapsed.total_seconds()/60:.1f} min)")
    print()
    print("📊 Training Summary:")
    print(f"   - Vulnerability Classifier: Final Val Acc = {vuln_history['val_acc'][-1]:.2f}%")
    print(f"   - Malware Detector: Final Val Acc = {malware_history['val_acc'][-1]:.2f}%")
    print(f"   - Threat Risk Scorer: Final Val Acc = {threat_history['val_acc'][-1]:.2f}%")
    print()
    print("📁 Trained Models:")
    print("   - trained_models/vulnerability_classifier.pth")
    print("   - trained_models/malware_detector.pth")
    print("   - trained_models/threat_risk_scorer.pth")
    print()
    print("🎯 Ready for deployment to FastAPI service!")


if __name__ == "__main__":
    main()
