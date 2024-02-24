FROM python:3-alpine

COPY src /opt/opencti-worker

WORKDIR /opt/opencti-worker

RUN apk --no-cache add git build-base libmagic libffi-dev \
    && pip3 install --no-cache-dir --requirement requirements.txt \
    && apk del git build-base

ENTRYPOINT ["python3"]
CMD ["worker.py"]
