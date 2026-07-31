# core/temporal_scorer.py

# Will enhance the agent by providing a temporal risk scoring.
# Scores indicators based on recency, activity windows and detection velocity
# Aids in surfacing early warning signals for IOCs.

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Recency threshold in days
RECENT_THRESHOLD = 30       # Indicators seen within 30 days
STALE_THRESHOLD = 730       # Indicators not seen in 2 years
VELOCITY_WINDOW = 7         # Detection spike window in days
NEW_INDICATOR_THRESHOLD = 14  # Indicators first seen within 14 days flag as new


class TemporalScorer:
    """
    Scores indicators based on temporal signals extracted from pivot results.
    Surfaces early warning signals for newly observed or rapidly accelerating threat indicators.
    """

    def __init__(self):
        self.now = datetime.now(timezone.utc)

    def _parse_timestamp(self, ts) -> datetime | None:
        """
        Parses a timestamp string or epoch milliseconds into a timezone-aware
        datetime object. Returns None if unparseable.
        """
        if not ts or ts == "unknown":
            return None

        try:
            # Epoch milliseconds from PassiveDNS
            if isinstance(ts, (int, float)) and ts > 1e10:
                return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)

            # Epoch seconds
            if isinstance(ts, (int, float)):
                return datetime.fromtimestamp(ts, tz=timezone.utc)

            # String timestamps from MalwareBazaar and crt.sh
            if isinstance(ts, str):
                formats = [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d",
                ]
                for fmt in formats:
                    try:
                        dt = datetime.strptime(ts, fmt)
                        return dt.replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue

        except Exception:
            pass

        return None

    def _days_ago(self, dt: datetime) -> float:
        """
        Returns how many days ago a datetime was relative to now.
        Positive = in the past. Negative = in the future (data artifact).
        """
        if dt is None:
            return float("inf")
        return (self.now - dt).total_seconds() / 86400

    def _recency_score(self, last_seen_days: float) -> float:
        """
        Scores how recently an indicator was observed.
        Recent activity = higher risk signal.
        0.0 = stale or unknown. 1.0 = seen today.
        """
        if last_seen_days == float("inf"):
            return 0.0
        if last_seen_days < 0:
            return 0.5  # Future date artifact — neutral
        if last_seen_days <= RECENT_THRESHOLD:
            return 1.0 - (last_seen_days / RECENT_THRESHOLD) * 0.3
        if last_seen_days >= STALE_THRESHOLD:
            return 0.0
        # Linear decay between recent and stale thresholds
        decay = (last_seen_days - RECENT_THRESHOLD) / (STALE_THRESHOLD - RECENT_THRESHOLD)
        return max(0.0, 0.7 - decay * 0.7)

    def _novelty_score(self, first_seen_days: float) -> float:
        """
        Scores how new an indicator is.
        Brand new indicators flag as higher risk — active campaign signal.
        0.0 = old/established. 1.0 = first seen within 24 hours.
        """
        if first_seen_days == float("inf"):
            return 0.0
        if first_seen_days <= NEW_INDICATOR_THRESHOLD:
            return 1.0 - (first_seen_days / NEW_INDICATOR_THRESHOLD) * 0.5
        return 0.0

    def extract_temporal_features(self, pivot_result: dict) -> dict:
        """
        Extracts all temporal signals from a pivot result.
        Pulls timestamps from PassiveDNS, MalwareBazaar, and crt.sh.
        Returns a flat dict of temporal features for scoring.
        """
        results = pivot_result.get("results", {})
        features = {
            "first_seen_days": float("inf"),
            "last_seen_days": float("inf"),
            "dns_record_age_days": float("inf"),
            "dns_record_recency_days": float("inf"),
            "bazaar_first_seen_days": float("inf"),
            "bazaar_last_seen_days": float("inf"),
            "cert_age_days": float("inf"),
            "related_sample_recency_days": float("inf"),
        }

        # PassiveDNS timestamps
        passivedns = results.get("passivedns", {})
        records = passivedns.get("records", [])
        if records:
            first_seens = []
            last_seens = []
            for record in records:
                fs = self._parse_timestamp(record.get("first_seen"))
                ls = self._parse_timestamp(record.get("last_seen"))
                if fs:
                    first_seens.append(fs)
                if ls:
                    last_seens.append(ls)
            if first_seens:
                features["dns_record_age_days"] = self._days_ago(min(first_seens))
            if last_seens:
                features["dns_record_recency_days"] = self._days_ago(max(last_seens))

        # MalwareBazaar timestamps
        bazaar = results.get("malwarebazaar", {})
        if bazaar.get("found"):
            fs = self._parse_timestamp(bazaar.get("first_seen"))
            ls = self._parse_timestamp(bazaar.get("last_seen"))
            if fs:
                features["bazaar_first_seen_days"] = self._days_ago(fs)
                features["first_seen_days"] = features["bazaar_first_seen_days"]
            if ls:
                features["bazaar_last_seen_days"] = self._days_ago(ls)
                features["last_seen_days"] = features["bazaar_last_seen_days"]

        # Related sample recency from MalwareBazaar tag cluster
        bazaar_related = results.get("malwarebazaar_related", {})
        samples = bazaar_related.get("samples", [])
        if samples:
            sample_dates = []
            for s in samples:
                fs = self._parse_timestamp(s.get("first_seen"))
                if fs:
                    sample_dates.append(fs)
            if sample_dates:
                most_recent = min(self._days_ago(d) for d in sample_dates)
                features["related_sample_recency_days"] = most_recent

        # Certificate transparency timestamps
        censys = results.get("censys", {})
        certs = censys.get("certificates", [])
        if certs:
            cert_dates = []
            for cert in certs:
                nb = self._parse_timestamp(cert.get("not_before"))
                if nb:
                    cert_dates.append(nb)
            if cert_dates:
                features["cert_age_days"] = self._days_ago(max(cert_dates))

        return features

    def score(self, pivot_result: dict) -> dict:
        """
        Main scoring method. Extracts temporal features and
        produces a normalized temporal risk score between 0 and 1.
        Higher scores indicate more temporally active or novel indicators.
        """
        features = self.extract_temporal_features(pivot_result)

        # Recency signal — how recently was this indicator active
        dns_recency = self._recency_score(features["dns_record_recency_days"])
        bazaar_recency = self._recency_score(features["bazaar_last_seen_days"])
        sample_recency = self._recency_score(features["related_sample_recency_days"])
        cert_recency = self._recency_score(features["cert_age_days"])

        # Take the strongest recency signal across all sources
        recency_score = max(dns_recency, bazaar_recency, sample_recency, cert_recency)

        # Novelty signal — how new is this indicator
        dns_novelty = self._novelty_score(features["dns_record_age_days"])
        bazaar_novelty = self._novelty_score(features["bazaar_first_seen_days"])
        cert_novelty = self._novelty_score(features["cert_age_days"])

        # Take the strongest novelty signal across all sources
        novelty_score = max(dns_novelty, bazaar_novelty, cert_novelty)

        # Weighted composite — recency weighted higher than novelty
        temporal_score = (recency_score * 0.6) + (novelty_score * 0.4)

        # Flag if any related samples were seen within velocity window
        early_warning = features["related_sample_recency_days"] <= VELOCITY_WINDOW

        return {
            "temporal_score": round(temporal_score, 4),
            "recency_score": round(recency_score, 4),
            "novelty_score": round(novelty_score, 4),
            "early_warning": early_warning,
            "features": features,
        }

    def blend_with_ml(self, ml_score: float, temporal_score: float) -> float:
        """
        Blends the ML confidence score with the temporal score.
        Weights: 75% ML, 25% temporal.
        Temporal acts as an amplifier for active/novel indicators.
        """
        blended = (ml_score * 0.75) + (temporal_score * 0.25)
        return round(min(blended, 1.0), 4)
    