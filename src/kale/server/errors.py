"""Errors of the service layer. The API maps each class to one HTTP status code."""

from __future__ import annotations


class ServiceError(Exception):
    """A request the service refuses; the message is shown to the client as ``detail``."""


class BadRequest(ServiceError):
    """A rule is broken: unknown module, kind not accepted, scope too wide, ..."""


class NotFound(ServiceError):
    pass


class Conflict(ServiceError):
    """The request does not fit the current state, such as cancelling a running job."""


class TooLarge(ServiceError):
    pass
