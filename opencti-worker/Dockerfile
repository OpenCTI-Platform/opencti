##############################
### Create base image fips or alpine
##############################

ARG BASE_TYPE=alpine
ARG BASE_IMAGE_ALPINE=python:3-alpine
ARG BASE_IMAGE_FIPS=filigran/python-nodejs-fips:latest

FROM ${BASE_IMAGE_ALPINE} AS base-alpine

FROM ${BASE_IMAGE_FIPS} AS base-fips

FROM base-${BASE_TYPE}

COPY src /opt/opencti-worker

WORKDIR /opt/opencti-worker

RUN apk --no-cache add git build-base libmagic libffi-dev \
    && pip3 install --no-cache-dir --requirement requirements.txt \
    && apk del git build-base

ENTRYPOINT ["python3"]
CMD ["worker.py"]
