"""Credentials shared by the API integration tests."""

TOKEN = "integration-" + "k" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
