import { ApolloServer } from '@apollo/server';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
import { print } from 'graphql';
import axios, { type AxiosInstance } from 'axios';
import createSchema from '../../src/graphql/schema';
import conf, { ACCOUNT_STATUS_ACTIVE, PORT } from '../../src/config/conf';
import { ADMINISTRATOR_ROLE, BYPASS, DEFAULT_ROLE, executionContext } from '../../src/utils/access';

// region static graphql modules
import '../../src/modules/index';
import type { AuthContext, AuthUser } from '../../src/types/user';
import type { StoreMarkingDefinition } from '../../src/types/store';
import { generateStandardId, MARKING_TLP_AMBER, MARKING_TLP_AMBER_STRICT, MARKING_TLP_CLEAR, MARKING_TLP_GREEN } from '../../src/schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_GROUP, ENTITY_TYPE_ROLE, ENTITY_TYPE_USER } from '../../src/schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../src/modules/organization/organization-types';
import type { ConfidenceLevel } from '../../src/generated/graphql';
import { findById } from '../../src/domain/user';
import { computeLoaders } from '../../src/http/httpAuthenticatedContext';
// endregion

export const SYNC_RAW_START_REMOTE_URI = conf.get('app:sync_raw_start_remote_uri');
export const SYNC_LIVE_START_REMOTE_URI = conf.get('app:sync_live_start_remote_uri');
export const SYNC_DIRECT_START_REMOTE_URI = conf.get('app:sync_direct_start_remote_uri');
export const SYNC_RESTORE_START_REMOTE_URI = conf.get('app:sync_restore_start_remote_uri');
export const SYNC_TEST_REMOTE_URI = `http://api-tests:${PORT}`;
export const SYNC_LIVE_EVENTS_SIZE = 631;

export const PYTHON_PATH = './src/python/testing';
export const API_URI = `http://localhost:${conf.get('app:port')}`;
export const ADMIN_API_TOKEN = conf.get('app:admin:token');
export const API_EMAIL = conf.get('app:admin:email');
export const API_PASSWORD = conf.get('app:admin:password');
const ONE_SECOND = 1000;
export const ONE_MINUTE = 60 * ONE_SECOND;
export const TEN_SECONDS = 10 * ONE_SECOND;
export const FIVE_MINUTES = 5 * ONE_MINUTE;
export const FIFTEEN_MINUTES = 300 * FIVE_MINUTES;

export const DATA_FILE_TEST = 'DATA-TEST-STIX2_v2.json';

export const testContext = executionContext('testing');
export const inPlatformContext = { ...testContext, user_inside_platform_organization: true };

export const generateBasicAuth = (email?: string, password?: string) => {
  const buff = Buffer.from(`${email ?? API_EMAIL}:${password ?? API_PASSWORD}`, 'utf-8');
  return `Basic ${buff.toString('base64')}`;
};

export const createHttpClient = (email?: string, password?: string) => {
  return wrapper(axios.create({
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      authorization: generateBasicAuth(email, password),
    },
  }));
};

export const createUnauthenticatedClient = () => {
  const jar = new CookieJar();
  return wrapper(axios.create({
    jar,
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
  }));
};

export const executeExternalQuery = async (client: AxiosInstance, uri: string, query: unknown, variables = {}) => {
  const response = await client.post(uri, { query, variables }, { withCredentials: true });
  const { data } = response.data;
  return data;
};

interface QueryOption {
  workId?: string;
  eventId?: string;
  previousStandard?: string;
  synchronizedUpsert?: string;
  applicantId?: string;
}
export const executeInternalQuery = async (client: AxiosInstance, query: unknown, variables = {}, options: QueryOption = {}) => {
  const headers: any = {};
  if (options.workId) headers['opencti-work-id'] = options.workId;
  if (options.eventId) headers['opencti-event-id'] = options.eventId;
  if (options.previousStandard) headers['previous-standard'] = options.previousStandard;
  if (options.synchronizedUpsert) headers['synchronized-upsert'] = options.synchronizedUpsert;
  if (options.applicantId) headers['opencti-applicant-id'] = options.applicantId;
  const response = await client.post(`${API_URI}/graphql`, { query, variables }, { withCredentials: true, headers });
  return response.data;
};
const adminClient = createHttpClient();
export const internalAdminQuery = async (query: unknown, variables = {}, options: QueryOption = {}) => {
  return executeInternalQuery(adminClient, query, variables, options);
};

// Roles
interface Role {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
}
export const TESTING_ROLES: Role[] = [];
const ROLE_PARTICIPATE: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Access knowledge and participate' }),
  name: 'Access knowledge and participate',
  description: 'Only participate',
  capabilities: ['KNOWLEDGE_KNPARTICIPATE', 'EXPLORE_EXUPDATE_EXDELETE'],
};
TESTING_ROLES.push(ROLE_PARTICIPATE);
export const ROLE_EDITOR: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Access knowledge/exploration and edit/delete' }),
  name: 'Access knowledge/exploration and edit/delete',
  description: 'Knowledge/exploration edit/delete',
  capabilities: [
    'KNOWLEDGE_KNUPDATE_KNDELETE',
    'KNOWLEDGE_KNUPDATE_KNMERGE',
    'EXPLORE_EXUPDATE_EXDELETE',
    'EXPLORE_EXUPDATE_PUBLISH',
    'TAXIIAPI_SETCOLLECTIONS',
    'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS',
  ],
};
TESTING_ROLES.push(ROLE_EDITOR);

export const ROLE_SECURITY: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Access knowledge/exploration/settings and edit/delete' }),
  name: 'Access knowledge/exploration/settings and edit/delete',
  description: 'Knowledge/exploration/settings edit/delete',
  capabilities: ['KNOWLEDGE_KNUPDATE_KNDELETE', 'KNOWLEDGE_KNUPDATE_KNMERGE', 'EXPLORE_EXUPDATE_EXDELETE', 'INVESTIGATION_INUPDATE_INDELETE', 'SETTINGS_SETACCESSES', 'SETTINGS_SECURITYACTIVITY', 'AUTOMATION_AUTMANAGE'],
};
TESTING_ROLES.push(ROLE_SECURITY);

// Maybe one day to be replaced by the connector built-in group
export const ROLE_TEST_CONNECTOR: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Test connector role' }),
  name: 'Test connector role',
  description: 'Access knowledge CRUD + connector, bypass ref, set marking, set labels',
  capabilities: [
    'KNOWLEDGE_KNUPDATE_KNDELETE',
    'KNOWLEDGE_KNUPDATE_KNMERGE',
    'KNOWLEDGE_KNUPLOAD',
    'KNOWLEDGE_KNASKIMPORT',
    'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
    'KNOWLEDGE_KNENRICHMENT',
    'CONNECTORAPI',
    'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE',
    'MODULES_MODMANAGE',
    'TAXIIAPI',
    'SETTINGS_SETMARKINGS',
    'SETTINGS_SETLABELS',
  ],
};
TESTING_ROLES.push(ROLE_TEST_CONNECTOR);

export const ROLE_DISINFORMATION_ANALYST: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Disinformation analyst: Access knowledge, data and label management' }),
  name: 'Disinformation analyst: Access knowledge, data and label management',
  description: 'Disinformation analyst: Access knowledge, data and label management',
  capabilities: [
    'KNOWLEDGE_KNPARTICIPATE',
    'KNOWLEDGE_KNUPDATE_KNDELETE',
    'KNOWLEDGE_KNUPDATE_KNMERGE',
    'KNOWLEDGE_KNUPLOAD',
    'KNOWLEDGE_KNASKIMPORT',
    'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT',
    'KNOWLEDGE_KNENRICHMENT',
    'EXPLORE_EXUPDATE',
    'INVESTIGATION_INUPDATE',
    'TAXIIAPI_SETCOLLECTIONS',
    'INGESTION_SETINGESTIONS',
    'CSVMAPPERS',
    'SETTINGS_SETLABELS',
  ],
};
TESTING_ROLES.push(ROLE_DISINFORMATION_ANALYST);

export const ROLE_PLATFORM_ADMIN: Role = {
  id: generateStandardId(ENTITY_TYPE_ROLE, { name: 'Platform configuration, connector configuration, manage public dashboard' }),
  name: 'Platform configuration, connector configuration, manage public dashboard',
  description: 'Platform configuration, connector configuration, manage public dashboard',
  capabilities: [
    'SETTINGS_SETPARAMETERS',
    'SETTINGS_SETACCESSES',
    'SETTINGS_SECURITYACTIVITY',
    'SETTINGS_FILEINDEXING',
    'SETTINGS_SUPPORT',
    'MODULES_MODMANAGE',
    'EXPLORE_EXUPDATE_PUBLISH',
  ],
};
TESTING_ROLES.push(ROLE_PLATFORM_ADMIN);

// Groups
export interface GroupTestData {
  id: string;
  name: string;
  markings: string[];
  roles: Role[];
  group_confidence_level: ConfidenceLevel;
  max_shareable_markings: string[];
}

export const TESTING_GROUPS: GroupTestData[] = [];

export const GREEN_GROUP: GroupTestData = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'GREEN GROUP' }),
  name: 'GREEN GROUP',
  markings: [MARKING_TLP_GREEN],
  roles: [ROLE_PARTICIPATE],
  group_confidence_level: {
    max_confidence: 50,
    overrides: [],
  },
  max_shareable_markings: [],
};
TESTING_GROUPS.push(GREEN_GROUP);

export const AMBER_GROUP: GroupTestData = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'AMBER GROUP' }),
  name: 'AMBER GROUP',
  markings: [MARKING_TLP_AMBER],
  roles: [ROLE_EDITOR],
  group_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  max_shareable_markings: [MARKING_TLP_GREEN],
};
TESTING_GROUPS.push(AMBER_GROUP);

export const AMBER_STRICT_GROUP: GroupTestData = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'AMBER STRICT GROUP' }),
  name: 'AMBER STRICT GROUP',
  markings: [MARKING_TLP_AMBER_STRICT],
  roles: [ROLE_SECURITY],
  group_confidence_level: {
    max_confidence: 80,
    overrides: [],
  },
  max_shareable_markings: [],
};
TESTING_GROUPS.push(AMBER_STRICT_GROUP);

export const CONNECTOR_GROUP: GroupTestData = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'TEST CONNECTOR GROUP' }),
  name: 'TEST CONNECTOR GROUP',
  markings: [MARKING_TLP_GREEN],
  roles: [ROLE_TEST_CONNECTOR],
  group_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  max_shareable_markings: [],
};
TESTING_GROUPS.push(CONNECTOR_GROUP);

export const GREEN_DISINFORMATION_ANALYST_GROUP: GroupTestData = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'GREEN DISINFORMATION ANALYST GROUP' }),
  name: 'GREEN DISINFORMATION ANALYST GROUP',
  markings: [MARKING_TLP_GREEN],
  roles: [ROLE_DISINFORMATION_ANALYST],
  group_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  max_shareable_markings: [],
};
TESTING_GROUPS.push(GREEN_DISINFORMATION_ANALYST_GROUP);

export const PLATFORM_ADMIN_GROUP: GroupTestData = {
  id: generateStandardId(ENTITY_TYPE_GROUP, { name: 'Platform admin group' }),
  name: 'Platform admin group',
  markings: [MARKING_TLP_CLEAR],
  roles: [ROLE_PLATFORM_ADMIN],
  group_confidence_level: {
    max_confidence: 10,
    overrides: [],
  },
  max_shareable_markings: [],
};
TESTING_GROUPS.push(PLATFORM_ADMIN_GROUP);

// Organization
export interface OrganizationTestData {
  name: string;
  id: string;
}

export const TESTING_ORGS: OrganizationTestData[] = [];
export const TEST_ORGANIZATION: OrganizationTestData = {
  name: 'TestOrganization',
  id: generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name: 'TestOrganization', identity_class: 'organization' }),
};
TESTING_ORGS.push(TEST_ORGANIZATION);

export const PLATFORM_ORGANIZATION: OrganizationTestData = {
  name: 'PlatformOrganization',
  id: generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name: 'PlatformOrganization', identity_class: 'organization' }),
};
TESTING_ORGS.push(PLATFORM_ORGANIZATION);

// Users
interface UserTestData {
  id: string;
  email: string;
  password: string;
  roles?: Role[];
  organizations?: OrganizationTestData[];
  groups: GroupTestData[];
  client: AxiosInstance;
}

export const ADMIN_USER: AuthUser = {
  administrated_organizations: [],
  entity_type: 'User',
  id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
  internal_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
  individual_id: undefined,
  organizations: [],
  name: 'admin',
  user_email: 'admin@opencti.io',
  roles: [ADMINISTRATOR_ROLE],
  groups: [],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
  default_marking: [],
  origin: { referer: 'test', user_id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f' },
  api_token: 'd434ce02-e58e-4cac-8b4c-42bf16748e84',
  account_status: ACCOUNT_STATUS_ACTIVE,
  account_lock_after_date: undefined,
  effective_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  user_confidence_level: {
    max_confidence: 100,
    overrides: [],
  },
  max_shareable_marking: [],
  restrict_delete: false,
  no_creators: false,
};
export const TESTING_USERS: UserTestData[] = [];
export const USER_PARTICIPATE: UserTestData = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'participate@opencti.io' }),
  email: 'participate@opencti.io',
  password: 'participate',
  organizations: [TEST_ORGANIZATION],
  groups: [GREEN_GROUP],
  client: createHttpClient('participate@opencti.io', 'participate'),
};
TESTING_USERS.push(USER_PARTICIPATE);
export const USER_EDITOR: UserTestData = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'editor@opencti.io' }),
  email: 'editor@opencti.io',
  password: 'editor',
  organizations: [TEST_ORGANIZATION],
  groups: [AMBER_GROUP],
  client: createHttpClient('editor@opencti.io', 'editor'),
};
TESTING_USERS.push(USER_EDITOR);

export const USER_SECURITY: UserTestData = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'security@opencti.io' }),
  email: 'security@opencti.io',
  password: 'security',
  organizations: [PLATFORM_ORGANIZATION],
  groups: [AMBER_STRICT_GROUP],
  client: createHttpClient('security@opencti.io', 'security'),
};
TESTING_USERS.push(USER_SECURITY);

export const USER_CONNECTOR: UserTestData = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'connector@opencti.io' }),
  email: 'connector@opencti.io',
  password: 'connector',
  groups: [CONNECTOR_GROUP],
  client: createHttpClient('connector@opencti.io', 'connector'),
};
TESTING_USERS.push(USER_CONNECTOR);

export const USER_DISINFORMATION_ANALYST: UserTestData = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'anais@opencti.io' }),
  email: 'anais@opencti.io',
  password: 'disinformation',
  organizations: [PLATFORM_ORGANIZATION],
  groups: [GREEN_DISINFORMATION_ANALYST_GROUP],
  client: createHttpClient('anais@opencti.io', 'disinformation'),
};
TESTING_USERS.push(USER_DISINFORMATION_ANALYST);

export const USER_PLATFORM_ADMIN: UserTestData = {
  id: generateStandardId(ENTITY_TYPE_USER, { user_email: 'platform@opencti.io' }),
  email: 'platform@opencti.io',
  password: 'platformadmin',
  groups: [PLATFORM_ADMIN_GROUP],
  client: createHttpClient('platform@opencti.io', 'platformadmin'),
};
TESTING_USERS.push(USER_PLATFORM_ADMIN);

// region group management
const GROUP_CREATION_MUTATION = `
  mutation groupCreation($input: GroupAddInput!) {
    groupAdd(input: $input) {
      id
    }
  }
`;
const GROUP_EDITION_MARKINGS_MUTATION = `
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
const GROUP_EDITION_SHAREABLE_MARKINGS_MUTATION = `
  mutation groupEdition($groupId: ID!, $input: [EditInput]!) {
    groupEdit(id: $groupId) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;
const GROUP_EDITION_ROLES_MUTATION = `
  mutation groupEdition($groupId: ID!, $toId: ID) {
    groupEdit(id: $groupId) {
      relationAdd(input: {
        toId: $toId
        relationship_type: "has-role"
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
const createGroup = async (input: GroupTestData): Promise<string> => {
  const { data } = await internalAdminQuery(GROUP_CREATION_MUTATION, {
    input: { name: input.name, group_confidence_level: input.group_confidence_level },
  });
  for (let index = 0; index < input.markings.length; index += 1) {
    const marking = input.markings[index];
    await internalAdminQuery(GROUP_EDITION_MARKINGS_MUTATION, { groupId: data.groupAdd.id, toId: marking });
  }
  for (let index = 0; index < input.max_shareable_markings.length; index += 1) {
    const maxMarking = input.max_shareable_markings[index];
    await internalAdminQuery(GROUP_EDITION_SHAREABLE_MARKINGS_MUTATION, { groupId: data.groupAdd.id,
      input: {
        key: 'max_shareable_markings',
        value: [{ type: 'TLP', value: maxMarking }],
      } });
  }
  for (let index = 0; index < input.roles.length; index += 1) {
    const role = input.roles[index];
    await internalAdminQuery(GROUP_EDITION_ROLES_MUTATION, { groupId: data.groupAdd.id, toId: role.id });
  }
  return data.groupAdd.id;
};
const assignGroupToUser = async (group: GroupTestData, user: UserTestData) => {
  await internalAdminQuery(GROUP_ASSIGN_MUTATION, { userId: user.id, toId: group.id });
};
// endregion

// region organization management
const ORGANIZATION_CREATION_MUTATION = `
  mutation organizationCreation($name: String!) {
     organizationAdd(input: {
      name: $name
    }) {
        id
        name
    }
  }
`;

const ORGANIZATION_ASSIGN_MUTATION = `
  mutation organizationAssign($userId: ID!, $toId: ID) {
    userEdit(id: $userId) {
      relationAdd(input: {
        toId: $toId
        relationship_type: "participate-to"
      }) {
        id
      }
    }
  }
`;
const createOrganization = async (input: { name: string }): Promise<string> => {
  const organization = await internalAdminQuery(ORGANIZATION_CREATION_MUTATION, input);
  return organization.data.organizationAdd.id;
};

const assignOrganizationToUser = async (organization: OrganizationTestData, user: UserTestData) => {
  await internalAdminQuery(ORGANIZATION_ASSIGN_MUTATION, { userId: user.id, toId: organization.id });
};
// endregion

export const adminQuery = async (request: any, options: QueryOption = {}) => {
  return internalAdminQuery(print(request.query), request.variables, options);
};

export const editorQuery = async (request: any, options: QueryOption = {}) => {
  return executeInternalQuery(USER_EDITOR.client, print(request.query), request.variables, options);
};

export const securityQuery = async (request: any) => {
  return executeInternalQuery(USER_SECURITY.client, print(request.query), request.variables);
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
const createRole = async (input: { name: string; description: string; capabilities: string[] }): Promise<string> => {
  const { data } = await internalAdminQuery(ROLE_CREATION_MUTATION, { name: input.name, description: input.description });
  for (let index = 0; index < input.capabilities.length; index += 1) {
    const capability = input.capabilities[index];
    const generateToId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: capability });
    await internalAdminQuery(ROLE_EDITION_MUTATION, { roleId: data.roleAdd.id, toId: generateToId });
  }
  return data.roleAdd.id;
};
// endregion

// region user management
const USER_CREATION_MUTATION = `
  mutation userCreation($email: String!, $name: String!, $password: String!) {
    userAdd(input: {
      user_email: $email
      name: $name
      password: $password
    }) {
      id
    }
  }
`;
const createUser = async (user: UserTestData) => {
  // Assign user to groups
  for (let indexGroup = 0; indexGroup < user.groups.length; indexGroup += 1) {
    const group = user.groups[indexGroup];
    // roles
    if (group.roles) {
      for (let index = 0; index < group.roles.length; index += 1) {
        const role = group.roles[index];
        await createRole(role);
      }
      await internalAdminQuery(USER_CREATION_MUTATION, {
        email: user.email,
        name: user.email,
        password: user.password,
      });
    }
    await createGroup(group);
    // Assign user to group
    await assignGroupToUser(group, user);
  }
  // Assign user to organizations
  if (user.organizations && user.organizations.length > 0) {
    for (let indexOrganization = 0; indexOrganization < user.organizations.length; indexOrganization += 1) {
      const organization = user.organizations[indexOrganization];
      await createOrganization(organization);
      await assignOrganizationToUser(organization, user);
    }
  }
};
// Create all testing users
export const createTestUsers = async () => {
  for (let index = 0; index < TESTING_USERS.length; index += 1) {
    const user = TESTING_USERS[index];
    await createUser(user);
  }
};
// Search for test users
const USERS_SEARCH_QUERY = `
  query usersTestSearchQuery($search: String) {
    users(search: $search) {
      edges {
        node {
          user_email
          id
        }
      }
    }
  }
`;
export const getUserIdByEmail = async (email: string) => {
  const { data } = await internalAdminQuery(USERS_SEARCH_QUERY, { search: `"${email}"` });
  if (!data?.users.edges.length) {
    return null;
  }
  return data.users.edges[0].node.id;
};
export const getAuthUser = async (id: string) => {
  const user = await findById(testContext, ADMIN_USER, id);
  return {
    ...user,
    origin: { referer: 'test', user_id: user.internal_id },
  } as AuthUser;
};
// endregion

// Search for test organizations
const ORGANIZATION_SEARCH_QUERY = `
  query OrganizationTestSearchQuery($search: String) {
    organizations(search: $search) {
      edges {
        node {
          name
          id
        }
      }
    }
  }
`;
export const getOrganizationIdByName = async (name: string) => {
  const { data } = await internalAdminQuery(ORGANIZATION_SEARCH_QUERY, { search: `"${name}"` });
  if (!data?.organizations.edges.length) {
    return null;
  }
  return data.organizations.edges[0].node.id;
};
// endregion

// Search for test group
const GROUP_SEARCH_QUERY = `
  query GroupTestSearchQuery($search: String) {
    groups(search: $search) {
      edges {
        node {
          name
          id
        }
      }
    }
  }
`;
export const getGroupIdByName = async (name: string) => {
  const { data } = await internalAdminQuery(GROUP_SEARCH_QUERY, { search: `"${name}"` });
  if (!data?.groups.edges.length) {
    return null;
  }
  return data.groups.edges[0].node.id;
};

// endregion

type markingType = { standard_id: string; internal_id: string };
export const buildStandardUser = (
  allowedMarkings: markingType[],
  allMarkings?: markingType[],
  capabilities?: { name: string }[],
  maxConfidence?: number,
): AuthUser => {
  return {
    administrated_organizations: [],
    entity_type: 'User',
    id: '88ec0c6a-12ce-5e39-b486-354fe4a7084f',
    internal_id: '98ec0c6a-13ce-5e39-b486-354fe4a7084f',
    individual_id: undefined,
    organizations: [],
    name: 'user',
    user_email: 'user@opencti.io',
    roles: [DEFAULT_ROLE],
    groups: [],
    capabilities: capabilities ?? [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }],
    allowed_marking: allowedMarkings as StoreMarkingDefinition[],
    default_marking: [],
    max_shareable_marking: [],
    origin: { referer: 'test', user_id: '98ec0c6a-13ce-5e39-b486-354fe4a7084f' },
    api_token: 'd434ce02-e58e-4cac-8b4c-42bf16748e85',
    account_status: ACCOUNT_STATUS_ACTIVE,
    account_lock_after_date: undefined,
    effective_confidence_level: {
      max_confidence: maxConfidence ?? 100,
      overrides: [],
    },
    user_confidence_level: {
      max_confidence: maxConfidence ?? 100,
      overrides: [],
    },
    restrict_delete: false,
    no_creators: false,
  };
};

// TODO: use a real healthcheck query
const HEALTHCHECK_QUERY = `
  query {
    about {
      version
    }
  }
`;

export const isPlatformAlive = async () => {
  const { data } = await internalAdminQuery(HEALTHCHECK_QUERY, { });
  return !!data?.about.version;
};

const serverFromUser = new ApolloServer<AuthContext>({
  schema: createSchema(),
  introspection: true,
  persistedQueries: false,
});

export const queryAsAdmin = async <T = Record<string, any>>(request: any, draftContext?: any) => {
  const execContext = executionContext('test', ADMIN_USER, draftContext ?? undefined);
  execContext.changeDraftContext = (draftId) => {
    execContext.draft_context = draftId;
  };
  execContext.batch = computeLoaders(execContext, ADMIN_USER);
  const { body } = await serverFromUser.executeOperation<T>(request, { contextValue: execContext });
  if (body.kind === 'single') {
    return body.singleResult;
  }
  return body.initialResult;
};

export const isSorted = (arr: []) => {
  let second_index;
  for (let first_index = 0; first_index < arr.length; first_index += 1) {
    second_index = first_index + 1;
    if (arr[second_index] - arr[first_index] < 0) return false;
  }
  return true;
};
