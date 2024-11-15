# Protect sensitive configuration

Some administrative actions and configuration modifications via the user interface can lead to data loss during ingestion, loss of data visibility for users, disruption of predefined automations, slowness
, etc.
To protect platforms from uncontrolled actions and make administrators' tasks easier, it is possible to restrict the modification of certain configurations to specific users.

## Concept

Protected elements are clearly identifiable, bounded by a block with an red border and a “Danger zone” chip.

![platform_organization_sensitive.png](assets%2Fplatform_organization_sensitive.png)

![role_administrator_sensitive_chip.png](assets%2Frole_administrator_sensitive_chip.png)

When a configuration is sensitive, it remains visible to user with access rights, but all
possible actions are disabled.

The sensitive configurations identified are:
- Modification of specific roles and groups
- Activation/deactivation of inference rules
- Main platform Organization modification
- Modification of specific marking definitions
- Enterprise Edition deactivation
- File indexing pause/reset

## Configuration

The configuration is done in the application configuration file. By default (in ``default.json``), ``platform_protected_sensitive_config`` is enabled.

It is possible to activate it around specific areas in the platform, as listed previously. It is also possible to choose which `Roles`, `Groups`  or `Marking definitions` will be protected.

By default, built-in `Groups` , `Roles` and `Markings` are protected:
- Roles ``default``, ``administrator`` and ``connector``
- Groups ``default``, ``administrators`` and ``connectors``
- Marking definitions ``TLP`` and ``PAP``

Once the platform is running, a platform administrator can restrict access to the sensitive configuration scoped in the platform settings through a capability in the RBAC, via ``Settings > Security > Roles > Capabilities list``.
Only users with `Allow modification of sensitive configuration` capability enabled will be able to modify sensitive configurations.

![check_allow_modification_sensitive_conf.png](assets%2Fcheck_allow_modification_sensitive_conf.png)

![role_allow_modification_sensitive_conf.png](assets%2Frole_allow_modification_sensitive_conf.png)

