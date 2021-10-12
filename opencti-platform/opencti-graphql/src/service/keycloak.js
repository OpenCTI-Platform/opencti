// Keycloak Admin Client
import KcAdminClient from '@keycloak/keycloak-admin-client';
import jwtDecode from 'jwt-decode';
import conf from '../config/conf';

const realm = conf.get('keycloak:realm');
const keycloakServer = conf.get('keycloak:server');
const clientId = conf.get('keycloak:client_id');
const clientSecret = conf.get('keycloak:client_secret');

const client = new KcAdminClient({ realmName: realm, baseUrl: keycloakServer });
// const validateJwt = (decoded) => {};

export const keycloakAlive = async () => {
  await client.auth({
    grantType: 'client_credentials',
    clientId,
    clientSecret,
  });
};

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

// eslint-disable-next-line import/prefer-default-export
export const getFromToken = async (headers) => {
  const expanded = expandToken(headers);
  const userRep = await client.users.findOne({ id: expanded.kcId });
  const xCyioClient = headers.get('x-cyio-client');
  return {
    id: userRep.id,
    firstName: userRep.firstName,
    lastName: userRep.lastName,
    email: userRep.email,
    active_client: xCyioClient,
  };
};
