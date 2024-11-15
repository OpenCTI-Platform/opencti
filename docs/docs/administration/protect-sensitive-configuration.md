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

## Recommended approach to give yourself access to danger zone

1. With a user having the capability “Manage credentials” or “Bypass all capbilities”, go into parameters/security
2. Create a new role called “Danger Zone Administration”.
3. Give it the capability **“**Allow modification of sensitive configuration”
4. Create a group “Danger Zone Administrator”
5. Add a user of your choice (yourself for instance): at this stage you should be all good

## Recommended approach to give administrator group access to danger zone

1. Follow the above steps
2. Once your user can manage the danger zone, go to the administrator group & assign the Danger Zone Administration role to it.
3. All your admins should not be able to edit anything flagged as danger zone.

## Disable the danger zone

1. Edit your config file to apply this configuration

```jsx
"protected_sensitive_config": {
      "enabled": false,
      "markings": {
        "enabled": true,
        "protected_definitions": ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED", "PAP:CLEAR", "PAP:GREEN", "PAP:AMBER", "PAP:AMBER"]
      },
      "groups": {
        "enabled": true,
        "protected_names": ["Administrators", "Connectors", "Default"]
      },
      "roles": {
        "enabled": true,
        "protected_names": ["Administrator", "Connector", "Default"]
      },
      "rules": {
        "enabled": true
      },
      "ce_ee_toggle": {
        "enabled": true
      },
      "file_indexing": {
        "enabled": true
      }
    }
  },
```
