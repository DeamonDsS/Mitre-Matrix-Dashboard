# ============================================================================
# ml/evaluate_model.py
# ============================================================================
"""Evaluate trained model on new data"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from config import *
from utils.feature_engineering import CyberKillChainFeatureExtractor


class ModelEvaluator:
    """Evaluate trained model"""
    
    def __init__(self, model_path: str, extractor_path: str = None):
        """
        Args:
            model_path: Path to saved model
            extractor_path: Path to feature extractor
        """
        # Load model
        model_artifact = joblib.load(model_path)
        self.model = model_artifact['model']
        self.phases = model_artifact['phases']
        self.feature_columns = model_artifact['feature_columns']
        
        # Load feature extractor
        if extractor_path:
            self.extractor = joblib.load(extractor_path)
        else:
            extractor_default = DATA_DIR / "feature_extractor.pkl"
            if extractor_default.exists():
                self.extractor = joblib.load(extractor_default)
            else:
                self.extractor = CyberKillChainFeatureExtractor()
        
        print(f"✓ Model loaded from {model_path}")
        print(f"✓ Feature extractor loaded")
    
    def predict(self, logs: list, return_proba: bool = False):
        """
        Make predictions on new logs
        
        Args:
            logs: List of log dictionaries
            return_proba: Whether to return probabilities
        
        Returns:
            predictions and optionally probabilities
        """
        # Extract features
        from utils.feature_engineering import extract_features
        df, _ = extract_features(logs, extractor=self.extractor, fit=False)
        
        # Align features
        df = self._align_features(df)
        
        # Predict
        predictions = self.model.predict(df)
        predicted_phases = [self.phases[p] for p in predictions]
        
        if return_proba:
            probabilities = self.model.predict_proba(df)
            return predicted_phases, probabilities
        
        return predicted_phases
    
    def predict_with_confidence(self, logs: list, threshold: float = 0.6):
        """
        Predict with confidence threshold
        
        Args:
            logs: List of log dictionaries
            threshold: Minimum confidence threshold
        
        Returns:
            List of dicts with phase, confidence, and all probabilities
        """
        phases, probas = self.predict(logs, return_proba=True)
        
        results = []
        for i, (phase, proba) in enumerate(zip(phases, probas)):
            max_confidence = proba.max()
            
            result = {
                'log_index': i,
                'predicted_phase': phase,
                'confidence': float(max_confidence),
                'meets_threshold': max_confidence >= threshold,
                'all_probabilities': {
                    self.phases[j]: float(proba[j]) 
                    for j in range(len(self.phases))
                }
            }
            results.append(result)
        
        return results
    
    def evaluate_on_labeled_data(self, logs: list):
        """
        Evaluate model on labeled data
        
        Args:
            logs: List of log dicts with 'phase' labels
        
        Returns:
            Evaluation metrics
        """
        # Extract true labels
        y_true = [self.phases.index(log['phase']) for log in logs]
        
        # Get predictions
        from utils.feature_engineering import extract_features
        df, _ = extract_features(logs, extractor=self.extractor, fit=False)
        df = self._align_features(df)
        
        y_pred = self.model.predict(df)
        
        # Metrics
        print("\n" + "="*60)
        print("EVALUATION RESULTS")
        print("="*60)
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=self.phases))
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        print("\nConfusion Matrix:")
        print(cm)
        
        return {
            'classification_report': classification_report(
                y_true, y_pred, 
                target_names=self.phases, 
                output_dict=True
            ),
            'confusion_matrix': cm
        }
    
    def _align_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Ensure features match training features"""
        # Add missing columns
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Keep only training columns in same order
        df = df[self.feature_columns]
        
        return df


def main():
    """Example usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Evaluate Kill Chain Model')
    parser.add_argument('--model', type=str, required=True, help='Path to model file')
    parser.add_argument('--data', type=str, help='Path to test data (optional)')
    parser.add_argument('--extractor', type=str, help='Path to feature extractor')
    
    args = parser.parse_args()
    
    # Load evaluator
    evaluator = ModelEvaluator(args.model, args.extractor)
    
    # Example prediction
    sample_logs = [
        {
            "message": "Nmap scan detected on port 22",
            "event_type": "network",
            "timestamp": "2025-10-30T10:00:00Z"
        },
        {
            "message": "Phishing email with malicious attachment received",
            "event_type": "email",
            "timestamp": "2025-10-30T10:05:00Z"
        },
        {
            "message": "Buffer overflow exploit attempt detected",
            "event_type": "security",
            "timestamp": "2025-10-30T10:10:00Z"
        }
    ]
    
    print("\nExample Predictions:")
    results = evaluator.predict_with_confidence(sample_logs, threshold=0.6)
    for result in results:
        print(f"\nLog {result['log_index']}:")
        print(f"  Phase: {result['predicted_phase']}")
        print(f"  Confidence: {result['confidence']:.3f}")
        print(f"  Meets threshold: {result['meets_threshold']}")
    
    # If test data provided, evaluate
    if args.data:
        import json
        with open(args.data, 'r') as f:
            test_logs = json.load(f)
        
        evaluator.evaluate_on_labeled_data(test_logs)


if __name__ == "__main__":
    main()