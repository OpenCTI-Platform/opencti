# upstream image
ARG PARENT_IMAGE="docker.io/python:3.10.2-alpine3.15"

# common packages
FROM "${PARENT_IMAGE}" as base

RUN apk --no-cache add libmagic libffi-dev \
    && pip3 install --no-cache-dir --upgrade pip \

WORKDIR /opt/opencti-worker

# build step including required compilation tools
FROM base as builder

ARG OPENCTI_VERSION="master"

COPY src /opt/opencti-worker

RUN apk --no-cache add git build-base \
    && pip3 install --no-cache-dir --upgrade --requirement requirements.txt \
    && pip3 install \
        --no-cache-dir \
        --upgrade \
        --force \
        "git+https://github.com/OpenCTI-Platform/client-python@${OPENCTI_VERSION}"

# final image with restricted privileges
FROM base

COPY --from=builder /opt/opencti-worker /opt/opencti-worker
COPY --from=builder /usr/local /usr/

USER nobody

ENTRYPOINT ["python3"]
CMD ["worker.py"]
