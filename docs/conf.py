# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os
import sys

# add main directory to path so that readthedocs can find main module
sys.path.append(os.path.abspath(".."))

project = "Web3 Policy Engine"
copyright = "2022, Daniel Neshyba-Rowe"
author = "Daniel Neshyba-Rowe"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinxcontrib.apidoc",
]

autodoc_typehints = "both"
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

apidoc_module_dir = "../web3_policy_engine"
apidoc_output_dir = "reference"
# apidoc_excluded_paths = []
apidoc_separate_modules = True


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
