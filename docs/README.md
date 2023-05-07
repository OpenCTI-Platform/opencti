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

Launch the local version
```
$ mkdocs serve
INFO    -  Building documentation...
INFO    -  Cleaning site directory
[I 160402 15:50:43 server:271] Serving on http://127.0.0.1:8000
[I 160402 15:50:43 handlers:58] Start watching changes
[I 160402 15:50:43 handlers:60] Start detecting changes
```

## Deploy the documentation

The documentation is deployed on Github pages trough a single command:
```
$ mkdocs gh-deploy
```