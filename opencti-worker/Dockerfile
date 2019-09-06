FROM python:3.7.4-alpine3.10

# Copy the worker
COPY src /opt/opencti-worker

# Install Python modules
RUN BUILD_WORKER=noninteractive \
    apk add build-base && \
    cd /opt/opencti-worker && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]
