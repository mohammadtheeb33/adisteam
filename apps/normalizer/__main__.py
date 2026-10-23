"""Run the normalization pipeline: ``python -m apps.normalizer``."""

import asyncio
import contextlib
import logging
import signal
import sys

from apps.normalizer.service import NormalizerService
from apps.normalizer.settings import NormalizerServiceSettings
from packages.config import ConfigurationError, load_settings
from packages.kafka import KafkaConfigurationError
from packages.observability import configure_logging

logger = logging.getLogger("adis.normalizer")

EXIT_OK = 0
EXIT_CONFIGURATION = 2


def main() -> int:
    """Load settings, configure JSON logging and consume until SIGINT/SIGTERM."""
    try:
        settings = load_settings(NormalizerServiceSettings)
    except ConfigurationError as error:
        logging.basicConfig(level=logging.ERROR, format="%(message)s")
        logger.error("%s", error)
        return EXIT_CONFIGURATION
    configure_logging(settings)
    try:
        asyncio.run(_serve(settings))
    except KafkaConfigurationError as error:
        logger.error("%s", error, extra={"action": "normalizer_configuration_error"})
        return EXIT_CONFIGURATION
    return EXIT_OK


async def _serve(settings: NormalizerServiceSettings) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Not supported on Windows; Ctrl+C then cancels the run, which still cleans up.
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)
    await NormalizerService.from_settings(settings).run(stop)


if __name__ == "__main__":
    sys.exit(main())
