# OpenCTI Documentation Space

[![Website](https://img.shields.io/badge/website-opencti.io-blue.svg)](https://opencti.io)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

## Introduction

This is the main repository of the OpenCTI Documentation space. The online version is available directly on [docs.opencti.io](https://docs.opencti.io).

## Install and display the documentation locally

Clone the repository:

```sh
git clone git@github.com:OpenCTI-Platform/opencti.git
cd docs
```

Install dependencies

```sh
pip install -r requirements.txt
```

Run local server with hot-reload:

```sh
mkdocs serve
```

It should display the following output in the terminal:
```
> Starting server at http://localhost:8000/
```

⚠️ Make sure to always build the documentation locally before submitting a pull request, and check for errors and warnings in the terminal output,as they can indicate issues with the formatting of the documentation.

```sh
mkdocs build
```


## Contribute

You can contribute to the documentation by submitting a pull request on GitHub. 
Please make sure to follow the [contribution guidelines](https://github.com/OpenCTI-Platform/opencti?tab=contributing-ov-file#contributing-to-opencti).

### Caveats

The following notable issues have been identified in the past and should be checked before submitting a pull request.

#### Bullet or ordered lists not rendered properly

```md
Some text
- Item 1
- Item 2
```

Will not be rendered properly, and displayed as a paragraph. 
To fix this, make sure to add a blank line before the first item in the list:

```md
Some text

- Item 1
- Item 2
```

#### Anchored links not working

When linking to a section in the same page, make sure to use the correct anchor link.
For instance:

```md
## My (super) section
```
Will be accessible with the following link: `#my-super-section` (all lowercase, spaces replaced by dashes, and special characters removed).

#### Documentation page not accessible from the sidebar

Make sure to add new documentation pages in the `mkdocs.yml` file under the `nav` section.
Then, make sure to build the documentation locally and check for errors and warnings in the terminal output.

## Deploy the documentation

The deployment relies on `mike`.

### Check existing versions

List existing versions with:

```sh
mike list
```

### Deploy and update the current version

With the right version number (eg. 5.7.X):

```sh
mike deploy --push [version]
```

### Deploy a new stable version

With the right version number (eg. 5.7.X), update the `latest` tag:

```sh
mike deploy --push --update-aliases [version] latest
```