# train_model.py

"""Train XGBoost model for cyber kill chain classification"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import xgboost as xgb
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Tuple
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    ConfusionMatrixDisplay,
    f1_score,
    accuracy_score
)
from imblearn.over_sampling import SMOTE
from datetime import datetime
from config import *


class KillChainModelTrainer:
    """Train and evaluate kill chain classifier"""
    
    def __init__(self, model_params: dict = None):
        self.model_params = model_params or MODEL_PARAMS
        self.model = None
        self.best_model = None
        self.feature_columns = None
        self.training_history = []
        
    def prepare_data(
        self, 
        df: pd.DataFrame,
        use_smote: bool = USE_SMOTE
    ) -> Tuple:
        """Prepare train/test splits"""
        X = df.drop(columns=["label"])
        y = df["label"]
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=TEST_SIZE, 
            random_state=RANDOM_STATE,
            stratify=y
        )
        
        print(f"\nTrain size: {len(X_train)}, Test size: {len(X_test)}")
        
        # Apply SMOTE if enabled
        if use_smote:
            print("Applying SMOTE for class balancing...")
            smote = SMOTE(
                k_neighbors=SMOTE_K_NEIGHBORS, 
                random_state=RANDOM_STATE
            )
            X_train, y_train = smote.fit_resample(X_train, y_train)
            print(f"After SMOTE: {len(X_train)} training samples")
        
        return X_train, X_test, y_train, y_test
    
    def train_model(
        self, 
        X_train: pd.DataFrame, 
        y_train: pd.Series,
        X_test: pd.DataFrame = None,
        y_test: pd.Series = None
    ):
        """Train XGBoost model"""
        print("\n" + "="*60)
        print("Training XGBoost Model")
        print("="*60)
        
        # Update params
        self.model_params["num_class"] = len(PHASES)
        
        # Create model
        self.model = xgb.XGBClassifier(**self.model_params)
        
        # Train with evaluation set
        eval_set = [(X_train, y_train)]
        if X_test is not None and y_test is not None:
            eval_set.append((X_test, y_test))
        
        self.model.fit(
            X_train, 
            y_train,
            eval_set=eval_set,
            verbose=True
        )
        
        # Store training history
        self.training_history = self.model.evals_result()
        
        print("\n✓ Model training completed")
        
    def cross_validate(
        self, 
        X: pd.DataFrame, 
        y: pd.Series, 
        cv: int = 5
    ) -> dict:
        """Perform cross-validation"""
        print(f"\nPerforming {cv}-fold cross-validation...")
        
        scoring = ['accuracy', 'f1_weighted', 'precision_weighted', 'recall_weighted']
        results = {}
        
        for score in scoring:
            scores = cross_val_score(
                self.model, 
                X, y, 
                cv=cv, 
                scoring=score,
                n_jobs=-1
            )
            results[score] = {
                'mean': scores.mean(),
                'std': scores.std(),
                'scores': scores
            }
            print(f"  {score}: {scores.mean():.3f} (+/- {scores.std():.3f})")
        
        return results
    
    def evaluate_model(
        self, 
        X_test: pd.DataFrame, 
        y_test: pd.Series
    ) -> dict:
        """Evaluate model performance"""
        print("\n" + "="*60)
        print("Model Evaluation")
        print("="*60)
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        f1_weighted = f1_score(y_test, y_pred, average='weighted')
        
        print(f"\nAccuracy: {accuracy:.3f}")
        print(f"F1 Score (weighted): {f1_weighted:.3f}")
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=PHASES))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        return {
            'accuracy': accuracy,
            'f1_weighted': f1_weighted,
            'y_pred': y_pred,
            'y_pred_proba': y_pred_proba,
            'confusion_matrix': cm
        }
    
    def plot_confusion_matrix(self, cm: np.ndarray, save_path: str = None):
        """Plot confusion matrix"""
        plt.figure(figsize=(12, 10))
        
        # Normalize confusion matrix
        cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        
        # Plot
        sns.heatmap(
            cm_normalized,
            annot=True,
            fmt='.2f',
            cmap='Blues',
            xticklabels=PHASES,
            yticklabels=PHASES,
            cbar_kws={'label': 'Proportion'}
        )
        
        plt.title('Confusion Matrix (Normalized)', fontsize=16, pad=20)
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✓ Confusion matrix saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_feature_importance(self, top_n: int = 20, save_path: str = None):
        """Plot feature importance"""
        importance = self.model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': importance
        }).sort_values('importance', ascending=False)
        
        plt.figure(figsize=(10, 8))
        top_features = feature_importance_df.head(top_n)
        
        plt.barh(range(len(top_features)), top_features['importance'])
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Importance Score')
        plt.title(f'Top {top_n} Feature Importance', fontsize=14, pad=20)
        plt.gca().invert_yaxis()
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✓ Feature importance plot saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
        
        return feature_importance_df
    
    def plot_training_history(self, save_path: str = None):
        """Plot training history"""
        if not self.training_history:
            print("No training history available")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(15, 5))
        
        # Training loss
        if 'validation_0' in self.training_history:
            train_metric = self.training_history['validation_0']['mlogloss']
            axes[0].plot(train_metric, label='Training')
            axes[0].set_xlabel('Iteration')
            axes[0].set_ylabel('Log Loss')
            axes[0].set_title('Training Loss')
            axes[0].legend()
            axes[0].grid(True, alpha=0.3)
        
        # Validation loss
        if 'validation_1' in self.training_history:
            val_metric = self.training_history['validation_1']['mlogloss']
            axes[1].plot(val_metric, label='Validation', color='orange')
            axes[1].set_xlabel('Iteration')
            axes[1].set_ylabel('Log Loss')
            axes[1].set_title('Validation Loss')
            axes[1].legend()
            axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✓ Training history saved to {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def hyperparameter_tuning(
        self, 
        X_train: pd.DataFrame, 
        y_train: pd.Series,
        param_grid: dict = None
    ):
        """Perform hyperparameter tuning with GridSearchCV"""
        print("\n" + "="*60)
        print("Hyperparameter Tuning")
        print("="*60)
        
        if param_grid is None:
            param_grid = {
                'n_estimators': [100, 150, 200],
                'max_depth': [4, 5, 6, 7],
                'learning_rate': [0.01, 0.05, 0.1],
                'subsample': [0.8, 0.9, 1.0],
                'colsample_bytree': [0.8, 0.9, 1.0]
            }
        
        base_model = xgb.XGBClassifier(
            objective='multi:softmax',
            num_class=len(PHASES),
            random_state=RANDOM_STATE,
            n_jobs=-1
        )
        
        grid_search = GridSearchCV(
            base_model,
            param_grid,
            cv=3,
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=2
        )
        
        print("\nSearching best parameters...")
        grid_search.fit(X_train, y_train)
        
        print(f"\n✓ Best parameters: {grid_search.best_params_}")
        print(f"✓ Best CV score: {grid_search.best_score_:.3f}")
        
        self.best_model = grid_search.best_estimator_
        self.model = self.best_model
        
        return grid_search.best_params_
    
    def save_model(self, model_path: str = None, include_metadata: bool = True):
        """Save trained model"""
        if model_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            model_path = MODEL_DIR / f"killchain_xgb_{timestamp}.pkl"
        
        model_artifact = {
            'model': self.model,
            'phases': PHASES,
            'phase_names': PHASE_NAMES,
            'feature_columns': self.feature_columns,
            'model_params': self.model_params,
            'timestamp': datetime.now().isoformat()
        }
        
        if include_metadata:
            model_artifact['metadata'] = {
                'n_features': len(self.feature_columns),
                'n_classes': len(PHASES),
                'framework': 'XGBoost',
                'version': xgb.__version__
            }
        
        joblib.dump(model_artifact, model_path)
        print(f"\n✓ Model saved to {model_path}")
        
        return model_path


def train_complete_pipeline(
    data_file: str = None,
    use_smote: bool = True,
    perform_tuning: bool = False,
    save_plots: bool = True
):
    """Complete training pipeline"""
    print("="*60)
    print("CYBER KILL CHAIN MODEL TRAINING PIPELINE")
    print("="*60)
    
    # Load data
    if data_file and Path(data_file).exists():
        print(f"\nLoading data from {data_file}...")
        df = pd.read_pickle(data_file)
    else:
        print("\nPreparing dataset from scratch...")
        from prepare_dataset import DatasetPreparer
        preparer = DatasetPreparer()
        df, extractor = preparer.build_dataset()
        
        # Save feature extractor
        extractor_file = DATA_DIR / "feature_extractor.pkl"
        joblib.dump(extractor, extractor_file)
        print(f"✓ Feature extractor saved to {extractor_file}")
    
    # Initialize trainer
    trainer = KillChainModelTrainer()
    
    # Prepare data
    X_train, X_test, y_train, y_test = trainer.prepare_data(df, use_smote=use_smote)
    
    # Hyperparameter tuning (optional)
    if perform_tuning:
        best_params = trainer.hyperparameter_tuning(X_train, y_train)
        trainer.model_params.update(best_params)
    
    # Train model
    trainer.train_model(X_train, y_train, X_test, y_test)
    
    # Cross-validation
    cv_results = trainer.cross_validate(X_train, y_train)
    
    # Evaluate
    eval_results = trainer.evaluate_model(X_test, y_test)
    
    # Generate plots
    if save_plots:
        plot_dir = LOGS_DIR / f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        plot_dir.mkdir(exist_ok=True)
        
        # Confusion matrix
        trainer.plot_confusion_matrix(
            eval_results['confusion_matrix'],
            save_path=plot_dir / "confusion_matrix.png"
        )
        
        # Feature importance
        feature_importance_df = trainer.plot_feature_importance(
            top_n=20,
            save_path=plot_dir / "feature_importance.png"
        )
        feature_importance_df.to_csv(plot_dir / "feature_importance.csv", index=False)
        
        # Training history
        trainer.plot_training_history(
            save_path=plot_dir / "training_history.png"
        )
        
        print(f"\n✓ All plots saved to {plot_dir}")
    
    # Save model
    model_path = trainer.save_model()
    
    # Print summary
    print("\n" + "="*60)
    print("TRAINING SUMMARY")
    print("="*60)
    print(f"Accuracy: {eval_results['accuracy']:.3f}")
    print(f"F1 Score: {eval_results['f1_weighted']:.3f}")
    print(f"Cross-validation F1: {cv_results['f1_weighted']['mean']:.3f} (+/- {cv_results['f1_weighted']['std']:.3f})")
    print(f"Model saved to: {model_path}")
    print("="*60)
    
    return trainer, eval_results


def main():
    """Main training execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train Cyber Kill Chain ML Model')
    parser.add_argument('--data', type=str, help='Path to training data pickle file')
    parser.add_argument('--no-smote', action='store_true', help='Disable SMOTE')
    parser.add_argument('--tune', action='store_true', help='Perform hyperparameter tuning')
    parser.add_argument('--no-plots', action='store_true', help='Skip saving plots')
    
    args = parser.parse_args()
    
    trainer, results = train_complete_pipeline(
        data_file=args.data,
        use_smote=not args.no_smote,
        perform_tuning=args.tune,
        save_plots=not args.no_plots
    )
    
    return trainer, results


if __name__ == "__main__":
    trainer, results = main()