class ConfigError(Exception):
    """Raised when required runtime configuration is missing or invalid."""


class ToolNotConfiguredError(Exception):
    """Raised when a real external security tool is requested but not configured."""


class KnowledgeBaseEmptyError(Exception):
    """Raised when Chroma has no usable documents."""


class DataUnavailableError(Exception):
    """Raised when requested local data does not exist."""
