// Keycloak Admin Client
import jwtDecode from 'jwt-decode';
import conf from '../config/conf';
import Keycloak from 'keycloak-connect'

import { defaultFieldResolver, GraphQLSchema } from 'graphql';
import { getDirective, MapperKind, mapSchema } from '@graphql-tools/utils';
import { auth, hasPermission, hasRole } from 'keycloak-connect-graphql';

export const authDirectiveTransformer = (schema, directiveName = 'auth') => {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
      const authDirective = getDirective(schema, fieldConfig, directiveName)?.[0];
      if (authDirective) {
        const { resolve = defaultFieldResolver } = fieldConfig;
        fieldConfig.resolve = auth(resolve);
      }
      return fieldConfig;
    }
  });
};

export const permissionDirectiveTransformer = (schema, directiveName = 'hasPermission') => {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
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
      return fieldConfig;
    }
  });
};

export const roleDirectiveTransformer = (schema, directiveName = 'hasRole') => {
  return mapSchema(schema, {
    [MapperKind.OBJECT_FIELD]: (fieldConfig) => {
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
      return fieldConfig;
    }
  });
};

const realm = conf.get('keycloak:realm');
const keycloakServer = conf.get('keycloak:server');
const clientId = conf.get('keycloak:client_id');
const secret = conf.get('keycloak:client_secret');

let keycloakInstance

export const keycloakAlive = async () => {
  try {
    keycloakInstance = new Keycloak({},{
      "auth-server-url": keycloakServer,
      resource: clientId,
      realm,
      credentials: {
        secret
      }
    })
    return true;
  } catch (e) {
    return false;
  }
};

export const getKeycloak = () => {
  return keycloakInstance
}

export const getKeycloakMiddleware = () => {
  return keycloakInstance.middleware()
}

export const expandToken = (headers) => {
  const authHeader = headers.authorization;
  if (authHeader === undefined) return undefined;
  const bearer = authHeader.substring(7);
  const decoded = jwtDecode(bearer);
  const memberClientIds = decoded.get('client_ids');
  const xCyioClient = headers.get('x-cyio-client');
  if (!memberClientIds.includes(xCyioClient)) return undefined;
  return {
    kcId: decoded.get('sub'),
    clientId: xCyioClient,
  };
};

export const getFromToken = async (headers) => {
  const expanded = expandToken(headers);
  const userRep = await adminClient.users.findOne({ id: expanded.kcId });
  const xCyioClient = headers.get('x-cyio-client');
  return {
    id: userRep.id,
    firstName: userRep.firstName,
    lastName: userRep.lastName,
    email: userRep.email,
    active_client: xCyioClient,
  };
};
