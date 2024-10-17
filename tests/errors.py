class NoiroError(Exception):
    pass


class ApicPostError(NoiroError):
    """Raised when APIC responds error-code for a given post transaction"""
    pass


class ApicDeleteError(NoiroError):
    """Raised when deletion of a resource fails"""
    pass


class ApicResourceNotFoundError(NoiroError):
    """Raised when a resource is not found in APIC MIT"""


class APICError(NoiroError):
    '''Raised when the APIC returns an error code.'''


class TimedOut(NoiroError):
    '''Raised after waiting too long.'''
