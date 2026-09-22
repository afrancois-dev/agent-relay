# The ops image is separate from the API image: it never gains a path to the
# database and never imports the application code. It ships the stdlib-only
# incident desk plus a pinned kubectl for the bounded executor.
FROM python:3.11-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG KUBECTL_VERSION=v1.31.4
RUN curl -sSLo /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl

WORKDIR /app
COPY ops /app/ops

# The responder holds a namespace-scoped ServiceAccount token, so it must not
# run as root. A dedicated unprivileged user limits the blast radius of any RCE
# in an evidence-collection dependency.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin responder \
    && mkdir -p /var/lib/incidents \
    && chown -R responder:responder /app /var/lib/incidents

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

USER responder
EXPOSE 8099
CMD ["python", "-m", "ops.desk"]
