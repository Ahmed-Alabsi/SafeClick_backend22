# apps/ai/services/model_service.py
"""
AI Model Service
────────────────
Handles loading the active XGBoost model and generating predictions.
Integrates with the optimized V2 architecture.
"""

import logging
import os
import json
from django.conf import settings
from apps.ai.models import AIModelVersion, AIPrediction
from apps.scans.models import Scan
from apps.core.utils.monitoring import monitor_engine

logger = logging.getLogger(__name__)

_model = None
_model_metadata = None

# Robust absolute path using settings.BASE_DIR
_MODEL_PATH = os.path.join(settings.BASE_DIR, "models", "xgboost_url_model.json")

def _load_model():
    """Loads the XGBoost model once into memory (lazy initialization)."""
    global _model
    
    if _model is not None:
        return
    
    model_path = os.path.normpath(_MODEL_PATH)
    
    if not os.path.exists(model_path):
        logger.warning(f"[ML Engine] Model not found at {model_path}. AI Engine disabled.")
        _model = False
        return
    
    try:
        import xgboost as xgb
        _model = xgb.Booster()
        _model.load_model(model_path)
        logger.info(f"[ML Engine] XGBoost model loaded successfully from {model_path}")
    except Exception as e:
        logger.error(f"[ML Engine] Failed to load model: {e}")
        _model = False

class ModelService:
    def __init__(self):
        self.active_db_model = self._get_db_model()
        _load_model()
        
    def _get_db_model(self):
        """Loads the currently deployed model version DB record for tracking."""
        try:
            return AIModelVersion.objects.filter(status='deployed').order_by('-deployed_at').first()
        except:
            return None
            
    @monitor_engine("ai_model")
    def predict(self, scan_record: Scan, features_dict: dict) -> dict:
        """
        Executes prediction using the loaded XGBoost model.
        Records the prediction in the DB for the learning feedback loop.
        """
        if self.active_db_model is None:
            return {
                "status": "disabled",
                "error": "AI model not deployed in Dashboard",
                "details": {
                    "verdict": "skipped",
                    "score": 0,
                    "confidence": 0.0
                }
            }

        features = features_dict.get('features', {})
        vector = features_dict.get('vector', [])
        version = features_dict.get('version', 2)
        
        score = 0
        verdict = "safe"
        confidence = 0.5
        
        if _model is False or _model is None:
            logger.warning("AI Model not loaded, returning safe default.")
        elif not vector:
            logger.warning("Feature vector is empty, returning safe default.")
        else:
            try:
                import xgboost as xgb
                from domain_analysis.services.feature_extractor import FEATURE_NAMES
                
                # Ensure the vector matches the exact feature names expected by XGBoost
                if len(vector) == len(FEATURE_NAMES):
                    dmatrix = xgb.DMatrix([vector], feature_names=FEATURE_NAMES)
                    probability = float(_model.predict(dmatrix)[0])
                    
                    score = int(probability * 100)
                    
                    if probability >= 0.5:
                        verdict = "malicious"
                        confidence = 0.85 + (probability - 0.5) * 0.3 # Scales up to 1.0
                    elif probability >= 0.3:
                        verdict = "suspicious"
                        confidence = 0.70
                    else:
                        verdict = "safe"
                        confidence = 0.90 - (probability * 0.5)
                        
                else:
                    logger.error(f"Feature vector length mismatch. Expected {len(FEATURE_NAMES)}, got {len(vector)}")
            except Exception as e:
                logger.error(f"Prediction error: {e}")
        
        # Record prediction for feedback loop
        try:
            AIPrediction.objects.create(
                scan=scan_record,
                model_version=self.active_db_model,
                url=scan_record.url,
                features_used=features,
                feature_schema_version=version,
                prediction=verdict,
                confidence=round(min(confidence, 1.0), 2),
                risk_score=score
            )
        except Exception as e:
            logger.error(f"Failed to save AIPrediction record: {e}")
        
        return {
            "status": "ok",
            "details": {
                "verdict": verdict,
                "score": score,
                "confidence": round(min(confidence, 1.0), 2)
            }
        }
