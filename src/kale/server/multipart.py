"""Read a multipart request part by part, so a file part can stream straight to its place.

Starlette's form parser stores every file part in a temporary file of its own before the
route sees it, which would put uploaded samples outside the quarantine. This reader hands
out each part's bytes as they arrive instead, on top of python-multipart's push parser.
"""

from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass

from python_multipart.exceptions import FormParserError
from python_multipart.multipart import MultipartParser, parse_options_header


class InvalidMultipart(ValueError):
    """The body is not the multipart document its headers announce."""


@dataclass(frozen=True, slots=True)
class Part:
    name: str
    filename: str | None


class MultipartReader:
    """Pull the parts of a ``multipart/form-data`` body out of its chunk stream."""

    def __init__(self, stream: AsyncIterator[bytes], content_type: str) -> None:
        _, params = parse_options_header(content_type)
        boundary = params.get(b"boundary")
        if not boundary:
            raise InvalidMultipart("the multipart body has no boundary")
        self._stream = stream
        # Parsed but not yet taken: a part's headers, a piece of its data, or None at its end.
        self._events: deque[Part | bytes | None] = deque()
        self._ended = False
        self._header_name = b""
        self._header_value = b""
        self._disposition = b""
        self._parser = MultipartParser(
            boundary,
            {
                "on_part_begin": self._on_part_begin,
                "on_part_data": self._on_part_data,
                "on_part_end": self._on_part_end,
                "on_header_field": self._on_header_field,
                "on_header_value": self._on_header_value,
                "on_header_end": self._on_header_end,
                "on_headers_finished": self._on_headers_finished,
            },
        )

    # python-multipart callbacks: they only record events for the async side to take.

    def _on_part_begin(self) -> None:
        self._disposition = b""

    def _on_part_data(self, data: bytes, start: int, end: int) -> None:
        self._events.append(bytes(data[start:end]))

    def _on_part_end(self) -> None:
        self._events.append(None)

    def _on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_name += data[start:end]

    def _on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._header_value += data[start:end]

    def _on_header_end(self) -> None:
        if self._header_name.lower() == b"content-disposition":
            self._disposition = self._header_value
        self._header_name = self._header_value = b""

    def _on_headers_finished(self) -> None:
        _, options = parse_options_header(self._disposition)
        if b"name" not in options:
            raise InvalidMultipart("a multipart part has no name")
        filename = options.get(b"filename")
        self._events.append(
            Part(
                name=options[b"name"].decode("utf-8", "replace"),
                filename=filename.decode("utf-8", "replace") if filename is not None else None,
            )
        )

    async def _feed(self) -> bool:
        """Parse one more chunk; ``False`` once the body has ended."""
        if self._ended:
            return False
        try:
            chunk = await anext(self._stream, None)
            if chunk is None:
                self._ended = True
                self._parser.finalize()
                return False
            self._parser.write(chunk)
        except FormParserError as exc:
            raise InvalidMultipart(f"invalid multipart body: {exc}") from None
        return True

    async def next_part(self) -> Part | None:
        """The next part's name and file name, or ``None`` after the last part."""
        while True:
            while self._events:
                event = self._events.popleft()
                if isinstance(event, Part):
                    return event
            if not await self._feed():
                return None

    async def data(self) -> AsyncIterator[bytes]:
        """The current part's bytes, as they arrive."""
        while True:
            while self._events:
                event = self._events[0]
                if isinstance(event, Part):  # the next part began: this one is over
                    return
                self._events.popleft()
                if event is None:
                    return
                yield event
            if not await self._feed():
                raise InvalidMultipart("the multipart body ended inside a part")

    async def read(self, limit: int) -> bytes | None:
        """The current part's bytes in memory, or ``None`` when there are over ``limit``."""
        data = bytearray()
        async for chunk in self.data():
            data += chunk
            if len(data) > limit:
                return None
        return bytes(data)
