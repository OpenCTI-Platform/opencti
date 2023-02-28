import Keycloak from 'keycloak-connect';
import { defaultFieldResolver } from 'graphql';
import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
import { auth, hasPermission, hasRole, KeycloakContext } from 'keycloak-connect-graphql';
import KeycloakAdminClient from '@darklight/keycloak-admin-client';
import conf, { logApp } from '../config/conf';

const realm = conf.get('keycloak:realm');
const keycloakServer = conf.get('keycloak:server');
const clientId = conf.get('keycloak:client_id');
const secret = conf.get('keycloak:client_secret');
const enabled = process.env.POLICY_ENFORCEMENT ? process.env.POLICY_ENFORCEMENT === '1' : false;

let keycloakInstance;

const keycloakAdminClient = new KeycloakAdminClient({
  serverUrl: keycloakServer,
  clientId,
  realm,
  credentials: {
    secret,
  },
});

export const keycloakEnabled = () => {
  return enabled;
};

const getKeycloak = () => {
  return keycloakInstance;
};

export const authDirectiveTransformer = (schema, directiveName = 'auth') => {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      if (keycloakEnabled()) {
        const authDirective = getDirective(schema, fieldConfig, directiveName)?.[0];
        if (authDirective) {
          const { resolve = defaultFieldResolver } = fieldConfig;
          fieldConfig.resolve = auth(resolve);
        }
      }
      return fieldConfig;
    },
  });
};

export const permissionDirectiveTransformer = (schema, directiveName = 'hasPermission') => {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      if (keycloakEnabled()) {
        const permissionDirective = getDirective(schema, fieldConfig, directiveName)?.[0];
        if (permissionDirective) {
          const { resolve = defaultFieldResolver } = fieldConfig;
          const keys = Object.keys(permissionDirective);
          let resources;
          if (keys.length === 1 && keys[0] === 'resources') {
            resources = permissionDirective[keys[0]];
            if (typeof resources === 'string') resources = [resources];
            if (Array.isArray(resources)) {
              resources = resources.map((val) => String(val));
            } else {
              throw new Error('invalid hasRole args. role must be a String or an Array of Strings');
            }
          } else {
            throw Error("invalid hasRole args. must contain only a 'role argument");
          }
          fieldConfig.resolve = hasPermission(resources)(resolve);
        }
      }
      return fieldConfig;
    },
  });
};

export const roleDirectiveTransformer = (schema, directiveName = 'hasRole') => {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      if (keycloakEnabled()) {
        const roleDirective = getDirective(schema, fieldConfig, directiveName)?.[0];
        if (roleDirective) {
          const { resolve = defaultFieldResolver } = fieldConfig;
          const keys = Object.keys(roleDirective);
          let role;
          if (keys.length === 1 && keys[0] === 'role') {
            role = roleDirective[keys[0]];
            if (typeof role === 'string') role = [role];
            if (Array.isArray(role)) {
              role = role.map((val) => String(val));
            } else {
              throw new Error('invalid hasRole args. role must be a String or an Array of Strings');
            }
          } else {
            throw Error("invalid hasRole args. must contain only a 'role argument");
          }
          fieldConfig.resolve = hasRole(role)(resolve);
        }
      }
      return fieldConfig;
    },
  });
};

export const keycloakAlive = async () => {
  try {
    logApp.info('[INIT] Authentication Keycloak admin client');
    await keycloakAdminClient.auth();
  } catch (e) {
    logApp.error(`[INIT] Keycloak admin client failed to authenticate`, e);
    throw e;
  }

  if (!keycloakEnabled()) return false;
  try {
    keycloakInstance = new Keycloak(
      {},
      {
        'auth-server-url': keycloakServer,
        resource: clientId,
        realm,
        credentials: {
          secret,
        },
      }
    );
    return true;
  } catch (e) {
    logApp.error(`[INIT] Failed to establish Keycloak Connect`, e);
    return false;
  }
};

export const configureKeycloakMiddleware = (route, expressApp) => {
  if (keycloakEnabled()) {
    expressApp.use(route, getKeycloak().middleware());
  }
};

export const applyKeycloakContext = (context, req) => {
  if (keycloakEnabled()) {
    context.kauth = new KeycloakContext({ req }, getKeycloak());
  }
};

export { keycloakAdminClient };
