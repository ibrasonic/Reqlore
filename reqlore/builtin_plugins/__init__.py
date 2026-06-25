"""Reqlore built-in plugins.

This directory ships plugin files that are auto-discovered by the
plugin registry on every install. Each ``.py`` here is a self-contained
plugin authored against ``reqlore.plugins_sdk`` exactly like a
user-installed plugin under ``~/.rlr/plugins``. Adding a file here
makes it available out of the box on every Reqlore install.

The ``__init__.py`` filename starts with ``_`` so the registry's
``_*.py`` skip rule excludes it from discovery (we don't want the
package marker treated as a plugin).
"""
