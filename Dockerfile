FROM alpine:3.22.2

ENV TZ=UTC

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache python3 py3-pip tzdata curl openssh-client docker-cli

# Copy requirements first for better caching
COPY requirements.txt /app/

# Install python dependencies
RUN export PIP_BREAK_SYSTEM_PACKAGES=1 && \
    pip3 install --no-cache-dir -Ur /app/requirements.txt

# Force cache invalidation
ENV BUILD_DATE="2025-12-17-FIX-CACHE-2"

# Copy application code
COPY docker-controller-bot.py /app/
COPY config.py /app/
COPY docker_update.py /app/
COPY schedule_manager.py /app/
COPY schedule_flow.py /app/
COPY migrate_schedules.py /app/
COPY locale /app/locale
COPY entrypoint.sh /app/

RUN chmod +x /app/entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "docker-controller-bot.py"]