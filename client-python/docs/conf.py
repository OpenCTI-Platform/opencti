# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

# Add the client-python directory to the path for pycti module discovery
# This works both when building from client-python/ locally and from repo root via ReadTheDocs
docs_dir = os.path.dirname(os.path.abspath(__file__))
client_python_dir = os.path.dirname(docs_dir)
sys.path.insert(0, client_python_dir)


# -- Project information -----------------------------------------------------

project = "OpenCTI Python Client"
copyright = "2025, Filigran"
author = "OpenCTI Project"

# The full version, including alpha/beta/rc tags
# Dynamically read from pycti to stay in sync
from pycti import __version__  # isort: skip

release = __version__

master_doc = "index"

autoapi_modules = {"pycti": {"prune": True}}

pygments_style = "sphinx"

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.inheritance_diagram",
    "autoapi.sphinx",
    "sphinx_autodoc_typehints",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]
