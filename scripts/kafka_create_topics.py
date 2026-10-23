"""Create the ADIS Kafka topics that do not exist yet. Safe to run repeatedly.

Reads KAFKA_* settings from the environment or .env, like every ADIS service:

    python scripts/kafka_create_topics.py
"""

import asyncio
import logging
import sys

from aiokafka.errors import KafkaError

from packages.config import ConfigurationError, KafkaSettings, load_settings
from packages.kafka import TopicAdministrationError, ensure_topics

logger = logging.getLogger("adis.scripts.kafka_create_topics")


async def main() -> int:
    """Ensure topics exist; return the process exit code."""
    try:
        settings = load_settings(KafkaSettings)
    except ConfigurationError as error:
        logger.error("%s", error)
        return 2
    try:
        created = await ensure_topics(settings)
    except TopicAdministrationError as error:
        logger.error("%s", error)
        return 1
    except KafkaError as error:
        logger.error(
            "cannot reach Kafka at %s (%s); is the broker running? Try `make kafka-up`.",
            settings.kafka_bootstrap_servers,
            type(error).__name__,
        )
        return 1
    if created:
        logger.info("created topics: %s", ", ".join(created))
    else:
        logger.info("all topics already exist")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    sys.exit(asyncio.run(main()))
