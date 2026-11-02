"""boto3 yerine gecen sahte oturum ve istemciler.

Her istemci, islem adi -> sonuc (dict ya da kwargs alan fonksiyon) eslemesidir.
Tanimsiz bir islem cagrilirsa test yuksek sesle kirilir.
"""

from __future__ import annotations

from typing import Any, Callable


class FakeClientError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeClient:
    def __init__(self, service: str, region: str, ops: dict[str, Any]):
        self.service = service
        self.region = region
        self.ops = ops
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def can_paginate(self, operation: str) -> bool:
        return False

    def __getattr__(self, operation: str) -> Callable[..., Any]:
        if operation.startswith("_"):
            raise AttributeError(operation)

        def call(**kwargs: Any) -> Any:
            self.calls.append((operation, kwargs))
            if operation not in self.ops:
                raise AssertionError(f"beklenmeyen cagri: {self.service}.{operation} ({self.region})")
            value = self.ops[operation]
            return value(**kwargs) if callable(value) else value

        return call


class FakeSession:
    """clients[(service, region)] ya da clients[service] (tum bolgeler) -> ops."""

    def __init__(self, clients: dict[Any, dict[str, Any]]):
        self.clients = clients
        self.made: dict[tuple[str, str], FakeClient] = {}

    def client(self, service: str, region_name: str | None = None) -> FakeClient:
        ops = self.clients.get((service, region_name), self.clients.get(service, {}))
        client = FakeClient(service, region_name or "", ops)
        self.made[(service, region_name or "")] = client
        return client
