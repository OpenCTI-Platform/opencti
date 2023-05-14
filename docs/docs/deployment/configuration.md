# Configuration

The purpose of this section is to learn how to configure OpenCTI to have it tailored for your production and development needs. 

Here are the configuration keys, for both containers (environment variables) and manual deployment.

!!! note "Parameters equivalence"
    
    The equivalent of a config variable in environment variables is the usage of a double underscores (`__`) for a level of config.

    For example:
    ```json
    "providers": {
      "ldap": {
        "strategy": "LdapStrategy"
      }
    }
    ```

    will become:
    ```bash
    PROVIDERS__LDAP__STRATEGY=LdapStrategy
    ```

    If you need to put a list of elements for the key, it must have a special formatting. Here is an example for redirect URIs for OpenID config:
    ```bash
    "PROVIDERS__OPENID__CONFIG__REDIRECT_URIS=[\"https://demo.opencti.io/auth/oic/callback\"]"
    ```

## Platform

### API & Frontend


### Dependencies


### Schedules & Engines



## Worker

The Python worker can be configured manually using the configuration file `config.yml` or through environment variables.

## ElasticSearch

If you want to adapt the memory consumption of ElasticSearch, you can use theses options:

```bash
# Add the followiung environment variable:
"ES_JAVA_OPTS=-Xms8g -Xmx8g"
```

This can be done in configuration file in the `jvm.conf` file.