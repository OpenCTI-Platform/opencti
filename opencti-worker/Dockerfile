# syntax=docker/dockerfile:1.7
FROM python:3.12-alpine

COPY src /opt/opencti-worker
WORKDIR /opt/opencti-worker

RUN --mount=type=bind,source=requirements.txt,target=requirements.txt <<EOT
    set -euxo pipefail

    apk --no-cache add libmagic

    apk --no-cache add -t .pip_deps git
    pip3 install --no-cache-dir --requirement requirements.txt
    apk del .pip_deps
    rm /var/log/apk.log
EOT

ENTRYPOINT ["python3"]
CMD ["worker.py"]
