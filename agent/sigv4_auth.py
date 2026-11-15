"""httpx auth that SigV4-signs requests for AWS_IAM-authorised AgentCore Gateways."""

from __future__ import annotations

from collections.abc import Generator

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

_SIGNED_HEADERS = {"host", "content-type", "accept", "mcp-session-id", "mcp-protocol-version"}


class SigV4HttpxAuth(httpx.Auth):
    """Sign each request with the caller's current AWS credentials."""

    requires_request_body = True

    def __init__(self, session: boto3.session.Session, region: str, service: str = "bedrock-agentcore") -> None:
        self._session = session
        self._region = region
        self._service = service

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        credentials = self._session.get_credentials()
        if credentials is None:
            raise RuntimeError("no AWS credentials available for SigV4 signing")
        headers = {k: v for k, v in request.headers.items() if k.lower() in _SIGNED_HEADERS}
        aws_request = AWSRequest(method=request.method, url=str(request.url), data=request.content, headers=headers)
        SigV4Auth(credentials.get_frozen_credentials(), self._service, self._region).add_auth(aws_request)
        for key in ("Authorization", "X-Amz-Date", "X-Amz-Security-Token"):
            if key in aws_request.headers:
                request.headers[key] = aws_request.headers[key]
        yield request
