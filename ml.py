"""
Machine learning detection layer.

Two models, two jobs:

  Random Forest    - supervised. Names the attack when it resembles something
                     in the training data.
  Isolation Forest - unsupervised. Flags traffic that simply does not look
                     like the benign baseline, including patterns no rule and
                     no label ever described.

Both are optional. If no model file is present the engine runs rules-only and
says so on the dashboard, rather than crashing at startup.
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

import numpy as np

from .schema import Alert, FlowFeatures, FEATURE_NAMES

log = logging.getLogger("nids.ml")

CLASSIFIER_FILE = "classifier.joblib"
ANOMALY_FILE = "anomaly.joblib"
SCALER_FILE = "scaler.joblib"

BENIGN_LABEL = "benign"

# Severity assigned per predicted class.
CLASS_SEVERITY = {
    "port_scan": "medium",
    "host_sweep": "medium",
    "syn_flood": "critical",
    "dos": "high",
    "brute_force": "high",
    "icmp_flood": "medium",
}


class MLDetector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.classifier = None
        self.anomaly = None
        self.scaler = None
        self.feature_names: List[str] = list(FEATURE_NAMES)
        self._load()

    # -- loading ---------------------------------------------------------

    def _load(self) -> None:
        try:
            import joblib
        except ImportError:
            log.warning("joblib not installed - running rules-only")
            return

        d = self.cfg.model_dir
        for attr, filename in (
            ("classifier", CLASSIFIER_FILE),
            ("anomaly", ANOMALY_FILE),
            ("scaler", SCALER_FILE),
        ):
            path = os.path.join(d, filename)
            if os.path.exists(path):
                try:
                    setattr(self, attr, joblib.load(path))
                    log.info("loaded %s", path)
                except Exception as exc:
                    log.error("could not load %s: %s", path, exc)

        if not self.available:
            log.warning(
                "no models in %s - running rules-only. "
                "Train them with: python train_model.py", d
            )

    @property
    def available(self) -> bool:
        return self.classifier is not None or self.anomaly is not None

    # -- inference -------------------------------------------------------

    def _prepare(self, features: FlowFeatures) -> np.ndarray:
        x = np.array([features.vector()], dtype=float)
        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
        if self.scaler is not None:
            x = self.scaler.transform(x)
        return x

    def evaluate(self, features: FlowFeatures) -> List[Alert]:
        if not self.available:
            return []
        if features.src_ip in set(self.cfg.whitelist):
            return []
        # Tiny windows carry almost no signal and are the main source of
        # false positives in an anomaly detector.
        if features.packet_count < self.cfg.ml_min_packets:
            return []

        x = self._prepare(features)
        alerts: List[Alert] = []

        supervised = self._classify(features, x)
        if supervised:
            alerts.append(supervised)

        # Only ask the anomaly detector when the classifier saw nothing. An
        # attack already named does not also need to be called "unusual".
        if not supervised:
            unsupervised = self._anomaly_score(features, x)
            if unsupervised:
                alerts.append(unsupervised)

        return alerts

    def _classify(self, features: FlowFeatures, x: np.ndarray) -> Optional[Alert]:
        if self.classifier is None:
            return None
        try:
            probs = self.classifier.predict_proba(x)[0]
            classes = list(self.classifier.classes_)
        except Exception as exc:
            log.debug("classifier failed: %s", exc)
            return None

        idx = int(np.argmax(probs))
        label, confidence = classes[idx], float(probs[idx])

        if label == BENIGN_LABEL or confidence < self.cfg.ml_confidence_floor:
            return None

        return Alert(
            threat_type=f"ml_{label}",
            src_ip=features.src_ip,
            severity=CLASS_SEVERITY.get(label, "medium"),
            detector="ml",
            confidence=round(confidence, 3),
            description=(
                f"Classifier labelled traffic from {features.src_ip} as "
                f"{label.replace('_', ' ')} with {confidence:.0%} confidence."
            ),
            evidence={
                "predicted_class": label,
                "confidence": round(confidence, 3),
                "top_features": self._top_features(features),
            },
        )

    def _anomaly_score(self, features: FlowFeatures, x: np.ndarray) -> Optional[Alert]:
        if self.anomaly is None:
            return None
        try:
            prediction = int(self.anomaly.predict(x)[0])   # -1 anomaly, 1 normal
            raw = float(self.anomaly.decision_function(x)[0])
        except Exception as exc:
            log.debug("anomaly detector failed: %s", exc)
            return None

        if prediction != -1:
            return None

        # decision_function is negative for anomalies; map it to 0..1 so the
        # dashboard can show one comparable confidence number for both models.
        confidence = min(1.0, max(0.0, -raw * 2))
        severity = "high" if confidence > 0.5 else "low"

        return Alert(
            threat_type="ml_anomaly",
            src_ip=features.src_ip,
            severity=severity,
            detector="ml",
            confidence=round(confidence, 3),
            description=(
                f"Traffic from {features.src_ip} does not match the learned "
                f"baseline for this network."
            ),
            evidence={
                "anomaly_score": round(raw, 4),
                "packets_per_sec": round(features.packets_per_sec, 1),
                "distinct_dst_ports": features.distinct_dst_ports,
                "top_features": self._top_features(features),
            },
        )

    def _top_features(self, features: FlowFeatures, n: int = 3) -> dict:
        """The few feature values most worth showing a human in the alert."""
        interesting = [
            "packets_per_sec", "distinct_dst_ports", "syn_ratio",
            "port_entropy", "distinct_dst_ips",
        ]
        vals = {k: round(float(getattr(features, k)), 2) for k in interesting}
        return dict(sorted(vals.items(), key=lambda kv: -kv[1])[:n])
