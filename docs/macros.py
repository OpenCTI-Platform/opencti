import logging
import os

log = logging.getLogger("mkdocs.plugins.macros")


def define_env(env):
    # Same value as the platform's app:enabled_dev_features; and same env variable
    enabled = {name.strip() for name in os.environ.get("APP__ENABLED_DEV_FEATURES", "").split(",") if name.strip()}
    log.info("Enabled dev features: %s", ", ".join(sorted(enabled)) or "none")

    @env.macro
    def flag(name):
        return "*" in enabled or name in enabled
