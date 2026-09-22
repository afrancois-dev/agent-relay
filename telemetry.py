"""OpenTelemetry wiring for Agent Relay.

Three signals, one join key:

* **Metrics** -- RED metrics (rate, errors, duration) plus task lifecycle
  counters, exported for Prometheus scraping on ``OTEL_METRICS_PORT``.
* **Traces** -- HTTP server spans from FastAPI and DB spans from SQLAlchemy,
  shipped over OTLP/HTTP to the collector.
* **Structured logs** -- one JSON object per line with the active
  ``trace_id``/``span_id`` so logs, traces, and metrics can be correlated.

Every signal carries the same ``release`` (``RELAY_RELEASE``) and
``environment`` labels, so a bad deploy can be isolated without guessing which
image produced a symptom.

Secrets never enter telemetry: the log formatter scrubs bearer tokens, agent
and claim tokens, credential JSON, and query strings before a record is
serialized, and the ``http.route`` label is used instead of the raw URL to keep
path parameters (and any token accidentally placed in a path) out of metrics.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from contextvars import ContextVar
from typing import Any, Callable

from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import start_http_server


SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "agent-relay")
SERVICE_VERSION = os.getenv("RELAY_RELEASE", os.getenv("GIT_SHA", "dev"))
ENVIRONMENT = os.getenv("RELAY_ENVIRONMENT", "production")
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
METRICS_PORT = int(os.getenv("OTEL_METRICS_PORT", "9464"))

_RESOURCE = Resource.create(
    {
        "service.name": SERVICE_NAME,
        "service.version": SERVICE_VERSION,
        "deployment.environment": ENVIRONMENT,
        "service.instance.id": os.getenv("HOSTNAME", "local"),
    }
)

# Instruments are created lazily in ``configure_telemetry`` so they bind to the
# real MeterProvider rather than the API's no-op default.
_http_requests: Any = None
_http_duration: Any = None
_task_events: Any = None
_errors: Any = None
_otlp_log_handler: list[Any] = [None]

_configured = False


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

_TOKEN_PATTERN = re.compile(r"\b(agt|clm)_[A-Za-z0-9_\-]{8,}")
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_SECRET_JSON_PATTERN = re.compile(
    r'(?i)"(token|claim_token|password|secret|enrollment_secret|authorization)"\s*:\s*"[^"]*"'
)
_QUERY_PATTERN = re.compile(r"\?[^\s\"]+")


def redact(value: str) -> str:
    """Remove credential-shaped strings from telemetry text."""

    value = _BEARER_PATTERN.sub("Bearer <redacted>", value)
    value = _SECRET_JSON_PATTERN.sub(r'"\1": "<redacted>"', value)
    value = _TOKEN_PATTERN.sub(r"\1_<redacted>", value)
    return value


class JsonLogFormatter(logging.Formatter):
    """One redacted JSON object per line, correlated with the active span."""

    def format(self, record: logging.LogRecord) -> str:
        span_context = trace.get_current_span().get_span_context()
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
            "service": SERVICE_NAME,
            "release": SERVICE_VERSION,
            "environment": ENVIRONMENT,
        }
        if span_context.is_valid:
            payload["trace_id"] = format(span_context.trace_id, "032x")
            payload["span_id"] = format(span_context.span_id, "016x")
        for field in ("http.method", "http.route", "http.status_code", "task_id", "incident_id"):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


# --------------------------------------------------------------------------- #
# Setup
# --------------------------------------------------------------------------- #


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    handlers: list[logging.Handler] = [handler]
    if _otlp_log_handler[0] is not None:
        handlers.append(_otlp_log_handler[0])
    root = logging.getLogger()
    root.handlers = handlers
    root.setLevel(os.getenv("RELAY_LOG_LEVEL", "INFO"))
    # Keep uvicorn's access logger on the same JSON stream.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "agent_relay"):
        logger = logging.getLogger(name)
        logger.handlers = handlers
        logger.propagate = False


def configure_telemetry() -> None:
    """Install providers and start the Prometheus scrape endpoint (idempotent)."""

    global _configured, _http_requests, _http_duration, _task_events, _errors
    if _configured:
        return

    base = OTLP_ENDPOINT.rstrip("/") if OTLP_ENDPOINT else None

    tracer_provider = TracerProvider(resource=_RESOURCE)
    if base:
        tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{base}/v1/traces")))
    trace.set_tracer_provider(tracer_provider)

    if base:
        # Canonical pipeline: OTLP -> Collector -> Prometheus/Loki/Tempo.
        metric_reader: Any = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=f"{base}/v1/metrics"))
        logger_provider = LoggerProvider(resource=_RESOURCE)
        logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{base}/v1/logs"))
        )
        set_logger_provider(logger_provider)
        _otlp_log_handler[0] = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
    else:
        # Local development without a collector: expose /metrics directly.
        metric_reader = PrometheusMetricReader()
        start_http_server(METRICS_PORT)
    metrics.set_meter_provider(MeterProvider(resource=_RESOURCE, metric_readers=[metric_reader]))

    _configure_logging()

    meter = metrics.get_meter("agent_relay")
    _http_requests = meter.create_counter(
        "relay_http_requests_total", description="HTTP requests by release, route and status."
    )
    _http_duration = meter.create_histogram(
        "relay_http_request_duration_seconds", unit="s", description="HTTP request latency."
    )
    _task_events = meter.create_counter(
        "relay_task_events_total", description="Task lifecycle events."
    )
    _errors = meter.create_counter(
        "relay_errors_total", description="Application errors by route and error code."
    )
    _configured = True


def instrument_app(app: Any) -> None:
    """Instrument an ASGI app's HTTP server spans."""

    configure_telemetry()
    FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())


def instrument_engine(engine: Any) -> None:
    try:
        SQLAlchemyInstrumentor().instrument(engine=engine, tracer_provider=trace.get_tracer_provider())
    except Exception:  # pragma: no cover - instrumentation must never break serving
        logging.getLogger("agent_relay").exception("SQLAlchemy instrumentation failed")


# --------------------------------------------------------------------------- #
# Metrics middleware + helpers
# --------------------------------------------------------------------------- #


def _route_label(request: Any) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


def request_observer_middleware() -> Callable:
    """Build an ASGI middleware factory that records RED metrics."""

    async def middleware(request: Any, call_next: Callable) -> Any:
        started = time.perf_counter()
        status = "500"
        try:
            response = await call_next(request)
            status = str(response.status_code)
            return response
        except Exception:
            raise
        finally:
            route = _route_label(request)
            attributes = {
                "release": SERVICE_VERSION,
                "method": request.method,
                "route": route,
                "status": status,
            }
            if _http_requests is not None:
                _http_requests.add(1, attributes)
                _http_duration.record(time.perf_counter() - started, attributes)
            if status.startswith("5") and _errors is not None:
                _errors.add(1, {"release": SERVICE_VERSION, "route": route, "error_code": "http_5xx"})

    return middleware


def record_error(route: str, error_code: str) -> None:
    if _errors is not None:
        _errors.add(1, {"release": SERVICE_VERSION, "route": route, "error_code": error_code})


def record_task_event(event: str) -> None:
    if _task_events is not None:
        _task_events.add(1, {"release": SERVICE_VERSION, "event": event})


__all__ = [
    "JsonLogFormatter",
    "configure_telemetry",
    "instrument_app",
    "instrument_engine",
    "record_error",
    "record_task_event",
    "redact",
    "request_observer_middleware",
]
