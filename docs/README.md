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
pip install mkdocs mkdocs-material mkdocs-git-authors-plugin mike mkdocs-git-committers-plugin-2
```

## Useful commands

Launch the local environment:
```
$ mkdocs serve
Starting server at http://localhost:8000/
```

List versions:
```
$ mike list
```

Launch versionned local environment:
```
$ mike serve
```

## Deploy new versions of the doc

### Deploy a new stable version

With the right version number (eg. 5.7), update the `latest` tag:
```
$ mike deploy --push --update-aliases [version] latest
```

### Deploy new next version

With the right version number (eg. 5.7), update the `next` tag:
```
$ mike deploy --push --update-aliases [version] next
```