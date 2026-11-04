"""Built-in modules. Each one is registered in pyproject.toml under ``kale.modules``.

Adapters (``auth_logs``, ``web_scan``) wrap an existing tool and translate its results
into the kale contract, so the tool itself never has to depend on kale.
"""
