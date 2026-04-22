from dataclasses import dataclass, asdict
from typing import Any, Optional

@dataclass
class EngineResult:
    engine: str
    status: str            # ok | error | timeout | skipped | disabled
    latency_ms: float
    data: Optional[Any] = None
    error: Optional[str] = None
    
    def to_dict(self):
        # Strict Unified Schema: No flattening, no guessing.
        return {
            "engine": self.engine,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "data": self.data if self.data is not None else {},
            "error": self.error
        }
