# OpenCTI Documentation Space

## Introduction

This is the main repository of the OpenCTI Documentation space. The online version is available directly on [docs.opencti.io](https://docs.opencti.io).

## Install the documentation locally

Clone the repository:
```
$ git clone git@github.com:OpenCTI-Platform/docs.git
```

Install dependencies
```
pip install mkdocs mkdocs-material mkdocs-git-authors-plugin mike
```

## Useful commands

Launch the local environment:
```
$ mike serve
Starting server at http://localhost:8000/
```

List versions:
```
$ mike list
```

## Deploy a new version of the doc

The documentation is deployed on Github pages trough a single command:
```
$ mike delete latest
$ mike deploy [version] latest
```