"""
Master script to generate all 3M datasets (1M each for vulnerabilities, malware, threat intel)
and prepare data for ML training.
"""

import sys
import os
from pathlib import Path
import json
import numpy as np
import pickle
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from vulnerability_dataset_generator import VulnerabilityDatasetGenerator
from malware_dataset_generator import MalwareDatasetGenerator
from threat_intelligence_generator import ThreatIntelligenceDatasetGenerator


class DataProcessor:
    """Process and prepare data for ML model training."""
    
    def __init__(self, data_dir: str = "./training_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
    
    def process_vulnerability_data(self, jsonl_file: str) -> dict:
        """Load and process vulnerability data for training."""
        print("🔄 Processing vulnerability data...")
        
        features = []
        labels = []
        
        with open(jsonl_file, 'r') as f:
            for i, line in enumerate(f):
                if (i + 1) % 200_000 == 0:
                    print(f"   ✓ Processed {i + 1:,} records")
                
                record = json.loads(line)
                
                # Extract features
                feature_vector = [
                    record.get('cvss_score', 0),
                    record.get('exploitability', 0),
                    1 if record.get('has_exploit_available') else 0,
                    1 if record.get('is_trending') else 0,
                    record.get('detection_count', 0) / 1000,  # Normalize
                    record.get('false_positive_rate', 0),
                    record.get('days_since_disclosure', 0) / 365,  # Normalize to years
                    1 if record.get('public_disclosure') else 0,
                    1 if record.get('active_in_wild') else 0,
                    1 if record.get('remediation_available') else 0,
                ]
                
                features.append(feature_vector)
                
                # Labels (severity as ordinal)
                severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                label = severity_map.get(record['severity'], 0)
                labels.append(label)
        
        print(f"✅ Processed {len(features):,} vulnerability samples")
        
        return {
            'features': np.array(features),
            'labels': np.array(labels),
            'feature_names': [
                'cvss_score', 'exploitability', 'has_exploit', 'is_trending',
                'detection_count_norm', 'false_positive_rate', 'days_since_norm',
                'public_disclosure', 'active_in_wild', 'remediation_available'
            ]
        }
    
    def process_malware_data(self, jsonl_file: str) -> dict:
        """Load and process malware data for training."""
        print("🔄 Processing malware data...")
        
        features = []
        labels = []
        
        threat_level_map = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        
        with open(jsonl_file, 'r') as f:
            for i, line in enumerate(f):
                if (i + 1) % 200_000 == 0:
                    print(f"   ✓ Processed {i + 1:,} records")
                
                record = json.loads(line)
                
                # Extract features
                feature_vector = [
                    record.get('entropy', 0) / 8,  # Normalize to 0-1
                    1 if record.get('is_packed') else 0,
                    1 if record.get('has_import_table') else 0,
                    record.get('import_count', 0) / 100,  # Normalize
                    1 if record.get('has_resource_section') else 0,
                    1 if record.get('has_debug_info') else 0,
                    record.get('strings_count', 0) / 5000,  # Normalize
                    record.get('suspicious_strings', 0) / 500,  # Normalize
                    record.get('behavior_count', 0) / 18,  # Normalize to max
                    record.get('network_connections', 0) / 50,  # Normalize
                    record.get('file_modifications', 0) / 100,  # Normalize
                    record.get('registry_modifications', 0) / 50,  # Normalize
                    record.get('virustotal_detected_by', 0) / 72,  # Normalize to VT engines
                ]
                
                features.append(feature_vector)
                
                label = threat_level_map.get(record['threat_level'], 0)
                labels.append(label)
        
        print(f"✅ Processed {len(features):,} malware samples")
        
        return {
            'features': np.array(features),
            'labels': np.array(labels),
            'feature_names': [
                'entropy_norm', 'is_packed', 'has_imports', 'import_count_norm',
                'has_resources', 'has_debug', 'strings_count_norm', 'suspicious_strings_norm',
                'behavior_count_norm', 'network_connections_norm', 'file_mods_norm',
                'registry_mods_norm', 'vt_detections_norm'
            ]
        }
    
    def process_threat_intel_data(self, jsonl_file: str) -> dict:
        """Load and process threat intelligence data for training."""
        print("🔄 Processing threat intelligence data...")
        
        features = []
        labels = []
        
        threat_level_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        
        with open(jsonl_file, 'r') as f:
            for i, line in enumerate(f):
                if (i + 1) % 200_000 == 0:
                    print(f"   ✓ Processed {i + 1:,} records")
                
                record = json.loads(line)
                
                # Extract features
                feature_vector = [
                    len(record.get('mitre_tactics', [])) / 14,  # Normalize to max tactics
                    1 if record.get('is_active') else 0,
                    1 if record.get('weaponized') else 0,
                    1 if record.get('has_poc') else 0,
                    record.get('detection_count', 0) / 72,  # Normalize
                    record.get('affected_organizations', 0) / 1000,  # Normalize
                    record.get('threat_score', 0) / 100,  # Already 0-100
                    record.get('confidence', 0),  # Already 0-1
                ]
                
                features.append(feature_vector)
                
                label = threat_level_map.get(record['threat_level'], 0)
                labels.append(label)
        
        print(f"✅ Processed {len(features):,} threat intelligence samples")
        
        return {
            'features': np.array(features),
            'labels': np.array(labels),
            'feature_names': [
                'tactics_norm', 'is_active', 'weaponized', 'has_poc',
                'detection_count_norm', 'affected_orgs_norm', 'threat_score_norm', 'confidence'
            ]
        }
    
    def save_processed_data(self, data: dict, output_file: str) -> None:
        """Save processed data as pickle for ML training."""
        with open(output_file, 'wb') as f:
            pickle.dump(data, f)
        
        print(f"💾 Saved to {output_file}")
        print(f"   - Features shape: {data['features'].shape}")
        print(f"   - Labels shape: {data['labels'].shape}")
        print(f"   - Label distribution:")
        
        unique, counts = np.unique(data['labels'], return_counts=True)
        for label, count in zip(unique, counts):
            pct = count / len(data['labels']) * 100
            print(f"      Label {label}: {count:,} ({pct:.1f}%)")


def main():
    """Main execution: Generate all datasets and process for training."""
    
    print("=" * 80)
    print("🚀 CYBER SPLOI - ML DATASET GENERATION")
    print("Generating 3,000,000 synthetic records for model training")
    print("=" * 80)
    print()
    
    output_dir = Path("./training_data")
    output_dir.mkdir(exist_ok=True)
    
    start_time = datetime.now()
    
    # STEP 1: Generate Vulnerability Dataset (1M records)
    print("📊 STEP 1: Vulnerability Dataset Generation")
    print("-" * 80)
    vuln_gen = VulnerabilityDatasetGenerator(output_dir=str(output_dir))
    vuln_gen.generate_dataset(count=1_000_000)
    print()
    
    # STEP 2: Generate Malware Dataset (1M records)
    print("📊 STEP 2: Malware Dataset Generation")
    print("-" * 80)
    malware_gen = MalwareDatasetGenerator(output_dir=str(output_dir))
    malware_gen.generate_dataset(count=1_000_000)
    print()
    
    # STEP 3: Generate Threat Intelligence Dataset (1M records)
    print("📊 STEP 3: Threat Intelligence Dataset Generation")
    print("-" * 80)
    threat_gen = ThreatIntelligenceDatasetGenerator(output_dir=str(output_dir))
    threat_gen.generate_dataset(count=1_000_000)
    print()
    
    # STEP 4: Process Data for ML Training
    print("🔄 STEP 4: Processing Data for ML Model Training")
    print("-" * 80)
    processor = DataProcessor(data_dir=str(output_dir))
    
    # Process vulnerability data
    print("\n📈 Processing Vulnerability Dataset...")
    vuln_data = processor.process_vulnerability_data(
        output_dir / "vulnerabilities_1m.jsonl"
    )
    processor.save_processed_data(
        vuln_data,
        output_dir / "vulnerability_training_data.pkl"
    )
    
    # Process malware data
    print("\n📈 Processing Malware Dataset...")
    malware_data = processor.process_malware_data(
        output_dir / "malware_1m.jsonl"
    )
    processor.save_processed_data(
        malware_data,
        output_dir / "malware_training_data.pkl"
    )
    
    # Process threat intelligence data
    print("\n📈 Processing Threat Intelligence Dataset...")
    threat_data = processor.process_threat_intel_data(
        output_dir / "threat_intelligence_1m.jsonl"
    )
    processor.save_processed_data(
        threat_data,
        output_dir / "threat_intel_training_data.pkl"
    )
    
    # Summary
    elapsed = datetime.now() - start_time
    print()
    print("=" * 80)
    print("✅ DATASET GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total Time: {elapsed.total_seconds():.1f} seconds ({elapsed.total_seconds()/60:.1f} minutes)")
    print()
    print("📁 Generated Files:")
    print(f"   - vulnerabilities_1m.jsonl (1,000,000 records)")
    print(f"   - malware_1m.jsonl (1,000,000 records)")
    print(f"   - threat_intelligence_1m.jsonl (1,000,000 records)")
    print(f"   - vulnerability_training_data.pkl (ML-ready)")
    print(f"   - malware_training_data.pkl (ML-ready)")
    print(f"   - threat_intel_training_data.pkl (ML-ready)")
    print()
    print("🎯 Total Records Generated: 3,000,000")
    print("📊 ML Training Data: Ready for model training")
    print()


if __name__ == "__main__":
    main()
