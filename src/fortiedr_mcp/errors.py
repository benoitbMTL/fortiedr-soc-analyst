class FortiEDRError(Exception):
    """Base error for the read-only FortiEDR integration layer."""


class FortiEDRConfigurationError(FortiEDRError):
    """Raised when the server configuration is incomplete or invalid."""


class FortiEDRAuthenticationError(FortiEDRError):
    """Raised when FortiEDR rejects the configured credentials."""


class FortiEDRAPIError(FortiEDRError):
    """Raised when a FortiEDR API request fails safely."""


class FortiEDRNotFoundError(FortiEDRError):
    """Raised when a requested FortiEDR record does not exist."""


class FortiEDRAnalysisError(FortiEDRError):
    """Raised when incident analysis cannot be completed safely."""


class FortiEDRSkillNotFoundError(FortiEDRAnalysisError):
    """Raised when a requested analysis skill is not registered."""


class FortiEDRValidationError(FortiEDRAnalysisError):
    """Raised when structured analysis data fails validation."""

    def __init__(self, message: str, *, details: list[str] | None = None):
        super().__init__(message)
        self.details = details or []


class FortiEDRPersistenceError(FortiEDRError):
    """Raised when analysis run persistence fails safely."""


class FortiEDRLLMConfigurationError(FortiEDRAnalysisError):
    """Raised when the configured LLM client is incomplete or invalid."""


class FortiEDRLLMTimeoutError(FortiEDRAnalysisError):
    """Raised when the configured LLM provider times out."""


class FortiEDRLLMResponseError(FortiEDRAnalysisError):
    """Raised when the LLM response is missing or malformed."""
