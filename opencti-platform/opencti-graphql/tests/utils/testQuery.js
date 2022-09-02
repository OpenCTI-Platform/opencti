import { ApolloServer } from 'apollo-server-express';
import axios from 'axios';
import createSchema from '../../src/graphql/schema';
import conf from '../../src/config/conf';
import { BYPASS, ROLE_ADMINISTRATOR } from '../../src/utils/access';

// region static graphql modules
import '../../src/modules/index';
// endregion

export const SYNC_RAW_START_REMOTE_URI = conf.get('app:sync_raw_start_remote_uri');
export const SYNC_LIVE_START_REMOTE_URI = conf.get('app:sync_live_start_remote_uri');
export const SYNC_DIRECT_START_REMOTE_URI = conf.get('app:sync_direct_start_remote_uri');
export const SYNC_RESTORE_START_REMOTE_URI = conf.get('app:sync_restore_start_remote_uri');
export const SYNC_TEST_REMOTE_URI = 'http://api-tests:4000';
export const RAW_EVENTS_SIZE = 433;
export const SYNC_LIVE_EVENTS_SIZE = 247;

export const PYTHON_PATH = './src/python';
export const API_URI = `http://localhost:${conf.get('app:port')}`;
export const API_TOKEN = conf.get('app:admin:token');
export const API_EMAIL = conf.get('app:admin:email');
export const API_PASSWORD = conf.get('app:admin:password');
const ONE_SECOND = 1000;
export const ONE_MINUTE = 60 * ONE_SECOND;
export const TEN_SECONDS = 10 * ONE_SECOND;
export const FIVE_MINUTES = 5 * ONE_MINUTE;
export const FIFTEEN_MINUTES = 300 * FIVE_MINUTES;

export const generateBasicAuth = () => {
  const buff = Buffer.from(`${API_EMAIL}:${API_PASSWORD}`, 'utf-8');
  return `Basic ${buff.toString('base64')}`;
};

export const executeExternalQuery = async (uri, query, variables = {}) => {
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

export const ADMIN_USER = {
  id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
  name: 'admin',
  user_email: 'admin@opencti.io',
  otp_activated: false,
  otp_validated: false,
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  groups: [],
  allowed_marking: [],
  origin: { source: 'test', user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f' },
};

export const serverFromUser = (user = ADMIN_USER) => {
  return new ApolloServer({
    schema: createSchema(),
    introspection: true,
    persistedQueries: false,
    context: () => ({ user }),
  });
};

const adminApolloServer = serverFromUser();
export const queryAsAdmin = (request) => adminApolloServer.executeOperation(request);
