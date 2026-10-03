#!/usr/bin/env python3
"""
Master orchestration script for Cyber Sploi ML system.
Generates datasets, trains models, deploys inference engines.
"""

import sys
import time
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import subprocess


class MLOrchestrator:
    """Orchestrates the complete ML pipeline."""
    
    def __init__(self, workspace_dir: str = "."):
        self.workspace_dir = Path(workspace_dir)
        self.start_time = datetime.now()
        self.results = {}
    
    def print_banner(self, title: str, char: str = "="):
        """Print formatted banner."""
        print()
        print(char * 80)
        print(f"  {title}")
        print(char * 80)
        print()
    
    def print_step(self, step: int, total: int, title: str):
        """Print step header."""
        print(f"\n{'='*80}")
        print(f"  STEP {step}/{total}: {title}")
        print(f"{'='*80}\n")
    
    def step_1_generate_datasets(self) -> bool:
        """Step 1: Generate 3M synthetic datasets."""
        self.print_step(1, 6, "DATASET GENERATION")
        
        try:
            script_path = (
                self.workspace_dir / 
                "ai-engine/data_generation/generate_all_datasets.py"
            )
            
            if not script_path.exists():
                print(f"❌ Script not found: {script_path}")
                return False
            
            print(f"🚀 Running: python {script_path}\n")
            
            start = time.time()
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(self.workspace_dir),
                capture_output=False
            )
            elapsed = time.time() - start
            
            if result.returncode == 0:
                print(f"\n✅ Dataset generation completed in {elapsed/60:.1f} minutes")
                self.results['dataset_generation'] = {
                    'status': 'success',
                    'duration_seconds': elapsed
                }
                return True
            else:
                print(f"\n❌ Dataset generation failed with code {result.returncode}")
                return False
        
        except Exception as e:
            print(f"❌ Error in dataset generation: {e}")
            return False
    
    def step_2_verify_data(self) -> bool:
        """Step 2: Verify generated datasets."""
        self.print_step(2, 6, "DATA VERIFICATION")
        
        try:
            data_dir = self.workspace_dir / "ai-engine/training_data"
            
            files_to_check = [
                "vulnerabilities_1m.jsonl",
                "malware_1m.jsonl",
                "threat_intelligence_1m.jsonl",
                "vulnerability_training_data.pkl",
                "malware_training_data.pkl",
                "threat_intel_training_data.pkl"
            ]
            
            all_exist = True
            for filename in files_to_check:
                filepath = data_dir / filename
                if filepath.exists():
                    size_mb = filepath.stat().st_size / (1024 * 1024)
                    print(f"✅ {filename}: {size_mb:.1f} MB")
                else:
                    print(f"❌ {filename}: NOT FOUND")
                    all_exist = False
            
            if all_exist:
                print("\n✅ All datasets verified successfully")
                self.results['data_verification'] = {'status': 'success'}
                return True
            else:
                print("\n⚠️  Some datasets missing")
                return False
        
        except Exception as e:
            print(f"❌ Error verifying data: {e}")
            return False
    
    def step_3_install_dependencies(self) -> bool:
        """Step 3: Install ML dependencies."""
        self.print_step(3, 6, "DEPENDENCY INSTALLATION")
        
        try:
            req_file = self.workspace_dir / "ai-engine/requirements-ml.txt"
            
            print("📦 Installing Python ML packages...\n")
            
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file)],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("✅ Dependencies installed successfully")
                self.results['dependencies'] = {'status': 'success'}
                return True
            else:
                print(f"❌ Dependency installation failed:")
                print(result.stderr)
                return False
        
        except Exception as e:
            print(f"❌ Error installing dependencies: {e}")
            return False
    
    def step_4_train_models(self) -> bool:
        """Step 4: Train all models."""
        self.print_step(4, 6, "MODEL TRAINING")
        
        try:
            script_path = (
                self.workspace_dir / 
                "ai-engine/training/model_trainer.py"
            )
            
            if not script_path.exists():
                print(f"❌ Script not found: {script_path}")
                return False
            
            print(f"🚀 Running: python {script_path}\n")
            print("⏱️  This may take 1-4 hours depending on hardware...\n")
            
            start = time.time()
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(self.workspace_dir),
                capture_output=False
            )
            elapsed = time.time() - start
            
            if result.returncode == 0:
                hours = elapsed / 3600
                print(f"\n✅ Model training completed in {hours:.1f} hours")
                self.results['model_training'] = {
                    'status': 'success',
                    'duration_seconds': elapsed
                }
                return True
            else:
                print(f"\n❌ Model training failed with code {result.returncode}")
                return False
        
        except Exception as e:
            print(f"❌ Error in model training: {e}")
            return False
    
    def step_5_verify_models(self) -> bool:
        """Step 5: Verify trained models."""
        self.print_step(5, 6, "MODEL VERIFICATION")
        
        try:
            models_dir = self.workspace_dir / "ai-engine/trained_models"
            
            models_to_check = [
                "vulnerability_classifier.pth",
                "malware_detector.pth",
                "threat_risk_scorer.pth"
            ]
            
            all_exist = True
            for model_file in models_to_check:
                model_path = models_dir / model_file
                if model_path.exists():
                    size_mb = model_path.stat().st_size / (1024 * 1024)
                    print(f"✅ {model_file}: {size_mb:.1f} MB")
                else:
                    print(f"❌ {model_file}: NOT FOUND")
                    all_exist = False
            
            if all_exist:
                print("\n✅ All models verified successfully")
                self.results['model_verification'] = {'status': 'success'}
                return True
            else:
                print("\n❌ Some models missing")
                return False
        
        except Exception as e:
            print(f"❌ Error verifying models: {e}")
            return False
    
    def step_6_summary(self) -> None:
        """Step 6: Generate summary report."""
        self.print_step(6, 6, "SUMMARY REPORT")
        
        total_time = datetime.now() - self.start_time
        
        print("📊 EXECUTION SUMMARY")
        print("-" * 80)
        
        for step_name, result in self.results.items():
            status = "✅" if result['status'] == 'success' else "❌"
            print(f"{status} {step_name}: {result['status']}")
        
        print("-" * 80)
        print(f"Total Execution Time: {total_time.total_seconds()/60:.1f} minutes")
        print()
        
        # System information
        import torch
        print("🖥️  SYSTEM INFORMATION")
        print("-" * 80)
        print(f"Python: {sys.version.split()[0]}")
        print(f"PyTorch: {torch.__version__}")
        print(f"CUDA Available: {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            print(f"GPU: {torch.cuda.get_device_name(0)}")
            print(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
        print()
        
        # Next steps
        print("📋 NEXT STEPS")
        print("-" * 80)
        print("1. Start AI service:")
        print("   python backend/services/ai-service/src/main.py")
        print()
        print("2. Access API docs:")
        print("   http://localhost:8000/api/v1/docs")
        print()
        print("3. Test predictions:")
        print("   curl -X POST http://localhost:8000/api/v1/analyze/vulnerability \\")
        print("     -H 'Content-Type: application/json' \\")
        print("     -d '{...}'")
        print()
        
        # Save results
        results_file = self.workspace_dir / "ml_pipeline_results.json"
        with open(results_file, 'w') as f:
            json.dump({
                'timestamp': self.start_time.isoformat(),
                'total_duration_seconds': total_time.total_seconds(),
                'results': self.results
            }, f, indent=2)
        
        print(f"💾 Results saved to: {results_file}")
        print()
    
    def run(self, skip_generation: bool = False) -> bool:
        """Run complete pipeline."""
        self.print_banner("CYBER SPLOI - ML PIPELINE ORCHESTRATION")
        
        # Step 1: Generate datasets
        if not skip_generation:
            if not self.step_1_generate_datasets():
                return False
        
        # Step 2: Verify data
        if not self.step_2_verify_data():
            return False
        
        # Step 3: Install dependencies
        if not self.step_3_install_dependencies():
            print("⚠️  Continuing anyway...")
        
        # Step 4: Train models
        if not self.step_4_train_models():
            return False
        
        # Step 5: Verify models
        if not self.step_5_verify_models():
            return False
        
        # Step 6: Summary
        self.step_6_summary()
        
        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Cyber Sploi ML Pipeline Orchestrator"
    )
    parser.add_argument(
        '--workspace',
        type=str,
        default='.',
        help='Workspace directory (default: current directory)'
    )
    parser.add_argument(
        '--skip-generation',
        action='store_true',
        help='Skip dataset generation (use existing data)'
    )
    
    args = parser.parse_args()
    
    orchestrator = MLOrchestrator(workspace_dir=args.workspace)
    success = orchestrator.run(skip_generation=args.skip_generation)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
