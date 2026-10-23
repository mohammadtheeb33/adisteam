"""Configuration of the ingestion API service."""

from packages.config import ApiSettings, AppSettings, KafkaSettings


class ApiServiceSettings(AppSettings, KafkaSettings, ApiSettings):
    """Settings the ingestion API loads: application, Kafka and API sections.

    It needs no database or Supabase credentials: the API only validates events and
    hands them to Kafka.
    """
