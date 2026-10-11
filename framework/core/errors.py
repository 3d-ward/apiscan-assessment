"""Framework exception hierarchy.

Every failure mode a caller may reasonably want to distinguish gets its own
type. Nothing here is raised for an assessment *result* -- a finding is data,
not an exception.
"""


class FrameworkError(Exception):
    """Base for every error raised by the framework."""


class ProfileError(FrameworkError):
    """A target profile is missing, malformed or fails schema validation."""


class SecretInProfileError(ProfileError):
    """A literal credential was found where an indirection was required.

    Raised by the profile loader. Credentials belong in the engagement's secret
    file and must be referenced as ``${ENV:NAME}``. Writing one into the profile
    would place it under version control alongside the rest of the config.
    """


class PathGuardError(FrameworkError):
    """A path would place engagement data inside the framework or the source."""


class ScopeViolation(FrameworkError):
    """A case was requested that the engagement scope policy forbids."""


class AuthorisationError(FrameworkError):
    """Scope-excluded execution was requested without a valid authorisation."""


class TransportError(FrameworkError):
    """The request could not be issued at all (not an HTTP error response)."""


class DependencyUnavailable(FrameworkError):
    """An optional dependency is absent.

    Callers should degrade and record NOT VERIFIED rather than fail the run.
    """

    def __init__(self, dependency, capability, install_hint=""):
        self.dependency = dependency
        self.capability = capability
        self.install_hint = install_hint
        msg = "%s requires %s, which is not available" % (capability, dependency)
        if install_hint:
            msg += " (install: %s)" % install_hint
        super(DependencyUnavailable, self).__init__(msg)


class CorpusError(FrameworkError):
    """A case corpus is internally inconsistent."""


class RegisterError(FrameworkError):
    """A findings register is inconsistent with the run data it cites."""
