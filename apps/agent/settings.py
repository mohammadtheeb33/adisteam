"""Configuration of the endpoint agent."""

from packages.config import AgentSettings, AppSettings


class AgentServiceSettings(AppSettings, AgentSettings):
    """Settings the agent loads.

    It holds only its own ingestion token: no Kafka, database or Supabase credentials,
    because it talks to the ingestion API alone.
    """
