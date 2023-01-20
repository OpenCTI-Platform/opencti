import { ApolloServer } from 'apollo-server-express';
import axios from 'axios';
import createSchema from '../../src/graphql/schema';
import conf, { PORT } from '../../src/config/conf';
import { BYPASS, executionContext, ROLE_ADMINISTRATOR } from '../../src/utils/access';

// region static graphql modules
import '../../src/modules/index';
import type { AuthUser } from '../../src/types/user';
// endregion

export const SYNC_RAW_START_REMOTE_URI = conf.get('app:sync_raw_start_remote_uri');
export const SYNC_LIVE_START_REMOTE_URI = conf.get('app:sync_live_start_remote_uri');
export const SYNC_DIRECT_START_REMOTE_URI = conf.get('app:sync_direct_start_remote_uri');
export const SYNC_RESTORE_START_REMOTE_URI = conf.get('app:sync_restore_start_remote_uri');
export const SYNC_TEST_REMOTE_URI = `http://api-tests:${PORT}`;
export const RAW_EVENTS_SIZE = 718;
export const SYNC_LIVE_EVENTS_SIZE = 513;

export const PYTHON_PATH = './src/python/testing';
export const API_URI = `http://localhost:${conf.get('app:port')}`;
export const API_TOKEN = conf.get('app:admin:token');
export const API_EMAIL = conf.get('app:admin:email');
export const API_PASSWORD = conf.get('app:admin:password');
const ONE_SECOND = 1000;
export const ONE_MINUTE = 60 * ONE_SECOND;
export const TEN_SECONDS = 10 * ONE_SECOND;
export const FIVE_MINUTES = 5 * ONE_MINUTE;
export const FIFTEEN_MINUTES = 300 * FIVE_MINUTES;

export const DATA_FILE_TEST = 'DATA-TEST-STIX2_v2.json';

export const testContext = executionContext('testing');

export const generateBasicAuth = () => {
  const buff = Buffer.from(`${API_EMAIL}:${API_PASSWORD}`, 'utf-8');
  return `Basic ${buff.toString('base64')}`;
};

export const executeExternalQuery = async (uri: string, query: unknown, variables = {}) => {
  const response = await axios({
    url: uri,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      authorization: generateBasicAuth(),
    },
    data: { query, variables },
  });
  const { data } = response.data;
  return data;
};

export const ADMIN_USER: AuthUser = {
  id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
  internal_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
  individual_id: undefined,
  organizations: [],
  name: 'admin',
  user_email: 'admin@opencti.io',
  roles: [{ name: ROLE_ADMINISTRATOR }],
  groups: [],
  capabilities: [{ name: BYPASS }],
  all_marking: [],
  allowed_organizations: [],
  inside_platform_organization: true,
  allowed_marking: [],
  origin: { referer: 'test', user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f' },
  api_token: 'd434ce02-e58e-4cac-8b4c-42bf16748e84',
};

export const serverFromUser = (user = ADMIN_USER) => {
  return new ApolloServer({
    schema: createSchema(),
    introspection: true,
    persistedQueries: false,
    context: () => {
      return executionContext('test', user);
    },
  });
};

const adminApolloServer = serverFromUser();
export const queryAsAdmin = (request: any) => adminApolloServer.executeOperation(request);

export const isSorted = (arr: []) => {
  let second_index;
  for (let first_index = 0; first_index < arr.length; first_index += 1) {
    second_index = first_index + 1;
    if (arr[second_index] - arr[first_index] < 0) return false;
  }
  return true;
};
