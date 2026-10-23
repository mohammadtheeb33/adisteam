"""Configuration of the normalization pipeline service."""

from packages.config import AppSettings, DatabaseSettings, KafkaSettings, NormalizerSettings


class NormalizerServiceSettings(AppSettings, KafkaSettings, DatabaseSettings, NormalizerSettings):
    """Settings the normalizer loads: application, Kafka, database and pipeline sections.

    It needs no Supabase API keys: it writes through the database connection only.
    """
