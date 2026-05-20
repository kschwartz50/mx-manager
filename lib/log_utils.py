"""Rich-based logging setup shared across the mx-manager project."""

import logging

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme


def setup_logging(
    *, verbose: bool = False, pretty: bool = True, timestamps: bool = True
) -> None:
    """Configure root logging using Rich.

    - verbose=True  -> DEBUG
    - verbose=False -> INFO
    - pretty=True   -> Rich formatting enabled
    - pretty=False  -> still uses RichHandler but with minimal formatting

    Idempotent: if handlers are already configured, we just update the level.
    """
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)

    if root.handlers:
        for h in root.handlers:
            h.setLevel(level)
        return

    custom_theme = Theme(
        {
            "repr.number": "green",
            "repr.string": "yellow",
            "repr.path": "bright_magenta",
            "repr.filename": "bright_magenta",
        }
    )

    console = Console(stderr=True, theme=custom_theme)

    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
        markup=True if pretty else False,
        show_time=True if timestamps else False,
        show_level=True,
        show_path=True if pretty else False,
        log_time_format="[%X]",
    )
    handler.setLevel(level)

    fmt = logging.Formatter("%(message)s")
    handler.setFormatter(fmt)

    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
