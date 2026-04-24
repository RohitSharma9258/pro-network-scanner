class VanguardException(Exception):
    """Base exception for Vanguard Titan."""
    pass

class ScannerError(VanguardException):
    """Raised when the scanner engine fails."""
    pass

class DatabaseError(VanguardException):
    """Raised when database operations fail."""
    pass

class PluginError(VanguardException):
    """Raised when a plugin fails."""
    pass

class AuthError(VanguardException):
    """Raised when authentication fails."""
    pass

class ValidationError(VanguardException):
    """Raised when input validation fails."""
    pass

class NetworkError(VanguardException):
    """Raised when network resolution or connectivity fails."""
    pass
