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
import re
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
# Read version from pycti/__init__.py without importing (avoids dependency issues)
def get_version():
    init_path = os.path.join(client_python_dir, "pycti", "__init__.py")
    with open(init_path, "r") as f:
        content = f.read()
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown"


release = get_version()
version = release

master_doc = "index"

pygments_style = "sphinx"

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.graphviz",
    "sphinx.ext.inheritance_diagram",
    "autoapi.extension",
    "sphinx_autodoc_typehints",
]

# Graphviz configuration
graphviz_output_format = "svg"
inheritance_graph_attrs = {
    "rankdir": "TB",
    "size": '"6.0, 8.0"',
}
inheritance_node_attrs = {
    "shape": "box",
    "fontsize": 10,
    "height": 0.25,
    "style": '"setlinewidth(0.5),filled"',
    "fillcolor": "white",
}

# Napoleon settings for Google/NumPy style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_type_aliases = None

# AutoAPI configuration for sphinx-autoapi
autoapi_type = "python"
autoapi_dirs = [os.path.join(client_python_dir, "pycti")]
autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
    "special-members",
]
autoapi_python_class_content = (
    "both"  # Include both class docstring and __init__ docstring
)
autoapi_member_order = "bysource"
autoapi_keep_files = False
autoapi_add_toctree_entry = True
# Ignore top-level __init__.py to prevent "Undocumented" for re-exported classes
# Classes will be documented in their original modules with proper docstrings
autoapi_ignore = ["*/pycti/__init__.py"]

# Mock imports for modules that can't be installed on ReadTheDocs
autodoc_mock_imports = [
    "magic",
    "pika",
    "stix2",
    "pydantic",
    "yaml",
    "requests",
    "cachetools",
    "prometheus_client",
    "opentelemetry",
    "deprecation",
    "fastapi",
    "uvicorn",
    "sseclient",
    "datefinder",
    "python_json_logger",
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
