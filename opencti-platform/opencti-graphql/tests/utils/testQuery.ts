import { ApolloServer } from 'apollo-server-express';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
import { print } from 'graphql';
import axios, { AxiosInstance } from 'axios';
import createSchema from '../../src/graphql/schema';
import conf, { PORT } from '../../src/config/conf';
import { BYPASS, executionContext, ROLE_ADMINISTRATOR } from '../../src/utils/access';

// region static graphql modules
import '../../src/modules/index';
import type { AuthUser } from '../../src/types/user';
import type { StoreMarkingDefinition } from '../../src/types/store';
import { generateStandardId, MARKING_TLP_AMBER, MARKING_TLP_GREEN } from '../../src/schema/identifier';
import {
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_USER
} from '../../src/schema/internalObject';
// endregion

export const SYNC_RAW_START_REMOTE_URI = conf.get('app:sync_raw_start_remote_uri');
export const SYNC_LIVE_START_REMOTE_URI = conf.get('app:sync_live_start_remote_uri');
export const SYNC_DIRECT_START_REMOTE_URI = conf.get('app:sync_direct_start_remote_uri');
export const SYNC_RESTORE_START_REMOTE_URI = conf.get('app:sync_restore_start_remote_uri');
export const SYNC_TEST_REMOTE_URI = `http://api-tests:${PORT}`;
export const RAW_EVENTS_SIZE = 719;
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

export const generateBasicAuth = (email?: string, password?: string) => {
  const buff = Buffer.from(`${email ?? API_EMAIL}:${password ?? API_PASSWORD}`, 'utf-8');
  return `Basic ${buff.toString('base64')}`;
};

export const createHttpClient = (email?: string, password?: string) => {
  const jar = new CookieJar();
  return wrapper(axios.create({
    withCredentials: true,
    jar,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      authorization: generateBasicAuth(email, password),
    },
  }));
};

export const executeExternalQuery = async (client: AxiosInstance, uri: string, query: unknown, variables = {}) => {
  const response = await client.post(uri, { query, variables }, { withCredentials: true });
  const { data } = response.data;
  return data;
};

const executeInternalQuery = async (client: AxiosInstance, query: unknown, variables = {}) => {
  const validateStatus = () => true;
  const response = await client.post(`${API_URI}/graphql`, { query, variables }, { withCredentials: true, validateStatus });
  return response.data;
};
const adminClient = createHttpClient();
export const adminQuery = async (query: unknown, variables = {}) => {
  return executeInternalQuery(adminClient, query, variables);
};

// Groups
interface Group { id: string, name: string, markings: string[] }
export const GREEN_GROUP: Group = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'GREEN GROUP' }),
  name: 'GREEN GROUP',
  markings: [MARKING_TLP_GREEN]
};
export const AMBER_GROUP: Group = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'AMBER GROUP' }),
  name: 'AMBER GROUP',
  markings: [MARKING_TLP_AMBER]
};
// Roles
interface Role { id: string, name: string, description: string, capabilities: string[] }
const ROLE_PARTICIPATE: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Access knowledge and participate' }),
  name: 'Access knowledge and participate',
  description: 'Only participate',
  capabilities: ['KNOWLEDGE_KNPARTICIPATE']
};
export const ROLE_EDITOR: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Access knowledge and edit/delete' }),
  name: 'Access knowledge and edit/delete',
  description: 'Knowledge edit/delete',
  capabilities: ['KNOWLEDGE_KNUPDATE_KNDELETE']
};
// Users
interface User { id: string, email: string, password: string, roles: Role[], groups: Group[], client: AxiosInstance }
export const USER_PARTICIPATE: User = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'participate@opencti.io' }),
  email: 'participate@opencti.io',
  password: 'participate',
  roles: [ROLE_PARTICIPATE],
  groups: [GREEN_GROUP],
  client: createHttpClient('participate@opencti.io', 'participate')
};
export const USER_EDITOR: User = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'editor@opencti.io' }),
  email: 'editor@opencti.io',
  password: 'editor',
  roles: [ROLE_EDITOR],
  groups: [AMBER_GROUP],
  client: createHttpClient('editor@opencti.io', 'editor')
};

// region group management
const GROUP_CREATION_MUTATION = `
  mutation groupCreation($name: String!) {
    groupAdd(input: {
      name: $name
    }) {
      id
    }
  }
`;
const GROUP_EDITION_MUTATION = `
  mutation groupEdition($groupId: ID!, $toId: ID) {
    groupEdit(id: $groupId) {
      relationAdd(input: {
        toId: $toId
        relationship_type: "accesses-to"
      }) {
        id
      }
    }
  }
`;
const GROUP_ASSIGN_MUTATION = `
  mutation groupAssign($userId: ID!, $toId: ID) {
    userEdit(id: $userId) {
      relationAdd(input: {
        toId: $toId
        relationship_type: "member-of"
      }) {
        id
      }
    }
  }
`;
const createGroup = async (input: { name: string, markings: string[] }): Promise<string> => {
  const { data } = await adminQuery(GROUP_CREATION_MUTATION, { name: input.name });
  for (let index = 0; index < input.markings.length; index += 1) {
    const marking = input.markings[index];
    await adminQuery(GROUP_EDITION_MUTATION, { groupId: data.groupAdd.id, toId: marking });
  }
  return data.groupAdd.id;
};
const assignGroupToUser = async (group: Group, user: User) => {
  await adminQuery(GROUP_ASSIGN_MUTATION, { userId: user.id, toId: group.id });
};
// endregion

export const editorQuery = async (request: any) => {
  return executeInternalQuery(USER_EDITOR.client, print(request.query), request.variables);
};
export const participantQuery = async (request: any) => {
  return executeInternalQuery(USER_PARTICIPATE.client, print(request.query), request.variables);
};

// region role management
const ROLE_CREATION_MUTATION = `
  mutation roleCreation($name: String!, $description: String) {
    roleAdd(input: {
      name: $name
      description: $description
    }) {
      id
    }
  }
`;
const ROLE_EDITION_MUTATION = `
  mutation roleEdition($roleId: ID!, $toId: ID) {
    roleEdit(id: $roleId) {
      relationAdd(input: {
        fromId: $roleId
        toId: $toId
        relationship_type: "has-capability"
      }) {
        id
      }
    }
  }
`;
const createRole = async (input: { name: string, description: string, capabilities: string[] }): Promise<string> => {
  const { data } = await adminQuery(ROLE_CREATION_MUTATION, { name: input.name, description: input.description });
  for (let index = 0; index < input.capabilities.length; index += 1) {
    const capability = input.capabilities[index];
    const generateToId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capability });
    await adminQuery(ROLE_EDITION_MUTATION, { roleId: data.roleAdd.id, toId: generateToId });
  }
  return data.roleAdd.id;
};
// endregion

// region user management
const USER_CREATION_MUTATION = `
  mutation userCreation($email: user_email_String_minLength_5_format_email, $name: name_String_NotNull_minLength_2!, $password: String!, $roles: [ID]) {
    userAdd(input: {
      user_email: $email
      name: $name
      password: $password
      roles: $roles
    }) {
      id
    }
  }
`;
export const createUser = async (user: User) => {
  // roles
  for (let index = 0; index < user.roles.length; index += 1) {
    const role = user.roles[index];
    await createRole(role);
  }
  const roleIds = user.roles.map((r) => r.name);
  await adminQuery(USER_CREATION_MUTATION, { email: user.email, name: user.email, password: user.password, roles: roleIds });
  // Assign user to groups
  for (let indexGroup = 0; indexGroup < user.groups.length; indexGroup += 1) {
    const group = user.groups[indexGroup];
    await createGroup(group);
    // Assign user to group
    await assignGroupToUser(group, user);
  }
};
// endregion

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

type markingType = { standard_id: string; internal_id: string };
export const buildStandardUser = (allowedMarkings: markingType[], allMarkings?: markingType[]): AuthUser => {
  return {
    id: '88ec0c6a-12ce-5e39-b486-354fe4a7084f',
    internal_id: '98ec0c6a-13ce-5e39-b486-354fe4a7084f',
    individual_id: undefined,
    organizations: [],
    name: 'user',
    user_email: 'user@opencti.io',
    roles: [{ name: 'User' }],
    groups: [],
    capabilities: [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }],
    all_marking: (allMarkings ?? []) as StoreMarkingDefinition[],
    allowed_organizations: [],
    inside_platform_organization: true,
    allowed_marking: allowedMarkings as StoreMarkingDefinition[],
    origin: { referer: 'test', user_id: '98ec0c6a-13ce-5e39-b486-354fe4a7084f' },
    api_token: 'd434ce02-e58e-4cac-8b4c-42bf16748e85',
  };
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
