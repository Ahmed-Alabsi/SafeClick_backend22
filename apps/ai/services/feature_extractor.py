# apps/ai/services/feature_extractor.py
"""
AI Feature Extractor (v2 Schema)
─────────────────────────────────
Extracts 45 pre-defined features from a URL for the XGBoost model.
Proxies the extraction logic to the optimized domain_analysis engine.
"""

from apps.ai.models import CURRENT_FEATURE_SCHEMA_VERSION
from domain_analysis.services.feature_extractor import extract_features, extract_features_vector

class FeatureExtractor:
    
    @staticmethod
    def extract(url: str, domain_analysis: dict = None) -> dict:
        """
        Extracts features using the optimized V2 extractor and attaches the current schema version.
        Note: The V2 extractor does not strictly require domain_analysis dictionary 
        as it computes features deterministically, but we accept it for signature compatibility.
        """
        # Call the new 45-feature extractor
        features = extract_features(url)
        
        # We can also generate the vector directly if needed
        vector = extract_features_vector(url)
        
        return {
            "version": CURRENT_FEATURE_SCHEMA_VERSION,
            "features": features,
            "vector": vector
        }
