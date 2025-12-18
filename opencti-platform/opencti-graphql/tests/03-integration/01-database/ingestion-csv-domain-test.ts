import { afterAll, beforeAll, describe, it, expect, vi } from 'vitest';
import gql from 'graphql-tag';
import { addIngestionCsv, deleteIngestionCsv, ingestionCsvAddAutoUser } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { adminQuery, PLATFORM_ORGANIZATION, USER_EDITOR } from '../../utils/testQuery';
import { type EditInput, IngestionAuthType, type IngestionCsv, type IngestionCsvAddAutoUserInput, type IngestionCsvAddInput } from '../../../src/generated/graphql';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { getFakeAuthUser, getOrganizationEntity } from '../../utils/domainQueryHelper';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { findDefaultIngestionGroups, groupEditField } from '../../../src/domain/group';
import type { BasicGroupEntity } from '../../../src/types/store';
import { findById as findUserById } from '../../../src/domain/user';
import { executionContext, SYSTEM_USER } from '../../../src/utils/access';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

const DELETE_USER_QUERY = gql`
  mutation userDelete($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

const READ_USER_QUERY = gql`
  query user($id: String!) {
    user(id: $id) {
      id
      name
      description
      user_service_account
      user_confidence_level {
        max_confidence
      }
    }
  }
`;
describe('Ingestion CSV domain - create CSV Feed coverage', async () => {
  const ingestionCreatedIds: string[] = [];
  let ingestionUser: AuthUser;
  let currentTestContext: AuthContext;
  let ingestionDefaultGroupId: string;

  beforeAll(async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    ingestionUser = getFakeAuthUser('CsvFeedIngestionDomain');
    ingestionUser.capabilities = [{ name: 'KNOWLEDGE' }, { name: 'INGESTION_SETINGESTIONS' }];
    currentTestContext = executionContext('testContext', ingestionUser);
  });

  afterAll(async () => {
    await unSetOrganization();
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    for (let i = 0; i < ingestionCreatedIds.length; i += 1) {
      await deleteIngestionCsv(currentTestContext, ingestionUser, ingestionCreatedIds[i]);
    }
  });

  it('should default group be set to Connector on startup', async () => {
    const ingestionDefaultGroups: BasicGroupEntity[] = await findDefaultIngestionGroups(currentTestContext, ingestionUser) as BasicGroupEntity[];
    expect(ingestionDefaultGroups.length).toBe(1);
    expect(ingestionDefaultGroups[0].name).toBe('Connectors');
    expect(ingestionDefaultGroups[0].auto_integration_assignation).toStrictEqual(['global']);
    ingestionDefaultGroupId = ingestionDefaultGroups[0].id;
  });

  it('should create a CSV Feed with auto user creation works fine without platform org', async () => {
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test auto user creation without platform org',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] CSV Feed to test auto user creation without platform org',
      automatic_user: true,
      confidence_level: 42,
    };
    const ingestionCreated = await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('CSV Feed to test auto user creation without platform org');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBeDefined();

    const createdUser = await findUserById(currentTestContext, SYSTEM_USER, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] CSV Feed to test auto user creation without platform org');
    expect(createdUser.user_confidence_level?.max_confidence).toBe(42);
    expect(createdUser.user_service_account).toBeTruthy();
    expect(createdUser.user_email.endsWith('@opencti.invalid'), `${createdUser.user_email} should ends with @opencti.invalid'`).toBeTruthy();
    const userInDefaultGroup: BasicGroupEntity[] = createdUser.groups.filter((group: BasicGroupEntity) => group.id === ingestionDefaultGroupId);
    expect(userInDefaultGroup[0].name).toBe('Connectors'); // just to check that user is in default ingestion group
    expect(createdUser.groups.length, 'Platform default group should not apply, only default ingestion group').toBe(1);
    expect(createdUser.organizations.length, 'There is no platform org, so user should not have an organization').toBe(0);
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });

  it('should create a CSV Feed with auto user creation works fine with platform org', async () => {
    await setOrganization(PLATFORM_ORGANIZATION);
    const platformOrganization = await getOrganizationEntity(PLATFORM_ORGANIZATION);

    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test auto user creation with platform org',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] CSV Feed to test auto user creation with platform org',
      automatic_user: true,
      confidence_level: 81,
    };
    const ingestionCreated = await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('CSV Feed to test auto user creation with platform org');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBeDefined();

    const createdUser = await findUserById(currentTestContext, SYSTEM_USER, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] CSV Feed to test auto user creation with platform org');
    expect(createdUser.user_service_account).toBeTruthy();
    expect(createdUser.user_confidence_level?.max_confidence).toBe(81);
    expect(createdUser.user_email.endsWith('@opencti.invalid'), `${createdUser.user_email} should ends with @opencti.invalid'`).toBeTruthy();
    const userInDefaultGroup: BasicGroupEntity[] = createdUser.groups.filter((group: BasicGroupEntity) => group.id === ingestionDefaultGroupId);
    expect(userInDefaultGroup[0].name).toBe('Connectors'); // just to check that user is in default ingestion group
    expect(createdUser.groups.length, 'Platform default group should not apply, only default ingestion group').toBe(1);
    if (!createdUser.user_service_account) {
      expect(createdUser.organizations.length, 'There is one platform org, so user should have one organization').toBe(1);
      expect(createdUser.organizations[0].id).toBe(platformOrganization.id);
    } else {
      expect(createdUser.organizations.length, 'There is one platform org, so user should not have organization').toBe(0);
    }
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });

  it('should create a CSV Feed with System user refused', async () => {
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test with system user',
      uri: 'http://fakefeed.invalid',
      user_id: '',
    };

    await expect(async () => {
      await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    }).rejects.toThrowError('You have not chosen a user responsible for data creation');
  });

  it('should create a CSV Feed with existing user, confidence should be ignored', async () => {
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test existing user setup',
      uri: 'http://fakefeed.invalid',
      user_id: USER_EDITOR.id,
      confidence_level: 88,
    };
    const ingestionCreated = await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('CSV Feed to test existing user setup');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBe(USER_EDITOR.id);

    const editorUser = await findUserById(currentTestContext, SYSTEM_USER, USER_EDITOR.id);
    expect(editorUser.user_service_account).toBeFalsy();
    expect(editorUser.user_confidence_level?.max_confidence).toBeUndefined();
    expect(editorUser.user_email).toBe('editor@opencti.io');
  });

  it('should create a CSV Feed with a strange name works fine', async () => {
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'MyFééd @ Testing @mail.fr 🌈🍅 - CSVフィードの作成',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] MyFééd @ Testing @mail.fr 🌈🍅 - CSVフィードの作成',
      automatic_user: true,
    };
    const ingestionCreated = await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('MyFééd @ Testing @mail.fr 🌈🍅 - CSVフィードの作成');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBeDefined();

    const createdUser = await findUserById(currentTestContext, SYSTEM_USER, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] MyFééd @ Testing @mail.fr 🌈🍅 - CSVフィードの作成');
    expect(createdUser.user_service_account).toBeTruthy();
    expect(createdUser.user_confidence_level?.max_confidence).toBeUndefined();
    expect(createdUser.user_email.endsWith('@opencti.invalid'), `${createdUser.user_email} should ends with @opencti.invalid'`).toBeTruthy();
    const userInDefaultGroup: BasicGroupEntity[] = createdUser.groups.filter((group: BasicGroupEntity) => group.id === ingestionDefaultGroupId);
    expect(userInDefaultGroup[0].name).toBe('Connectors'); // just to check that user is in default ingestion group
    expect(createdUser.groups.length, 'Platform default group should not apply, only default ingestion group').toBe(1);
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });

  it('should a CSV Feed with auto user creation be refused when no default group', async () => {
    // remove default group in config
    let input: [EditInput] = [{ key: 'auto_integration_assignation', value: [] }];
    await groupEditField(currentTestContext, SYSTEM_USER, ingestionDefaultGroupId, input);

    // Create feed
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Feed created with auto user by no default ingestion group in config',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] should not be created',
      automatic_user: true,
    };
    await expect(async () => {
      await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    }).rejects.toThrowError('You have not defined a default group for ingestion users');

    // put back default group
    input = [{ key: 'auto_integration_assignation', value: ['global'] }];
    await groupEditField(currentTestContext, SYSTEM_USER, ingestionDefaultGroupId, input);

    const ingestionDefaultGroups: BasicGroupEntity[] = await findDefaultIngestionGroups(currentTestContext, ingestionUser) as BasicGroupEntity[];
    expect(ingestionDefaultGroups.length).toBe(1);
    expect(ingestionDefaultGroups[0].name).toBe('Connectors');
    expect(ingestionDefaultGroups[0].auto_integration_assignation).toStrictEqual(['global']);
  });

  it('should a CSV Feed with auto user creation be refused when service account already exists', async () => {
    // Create feed
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'Feed not created because auto service account already exists',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] Feed not created because auto service account already exists',
      automatic_user: true,
    };
    // First call
    const firstIngestionCreated = await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    ingestionCreatedIds.push(firstIngestionCreated.id);
    // Second call with exact same parameters
    await expect(async () => {
      await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
    }).rejects.toThrowError('This service account already exists. Change the instance name to change the automatically created service account name');

    // Delete just created user
    const createdUser = await findUserById(currentTestContext, SYSTEM_USER, firstIngestionCreated.user_id);
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });
});

describe('Ingestion CSV domain - ingestionCsvAddAutoUser', async () => {
  let ingestionUser: AuthUser;
  let currentTestContext: AuthContext;
  let ingestionCreated: IngestionCsv;
  beforeAll(async () => {
    ingestionUser = getFakeAuthUser('CsvFeedIngestionDomain');
    ingestionUser.capabilities = [{ name: 'KNOWLEDGE' }, { name: 'INGESTION_SETINGESTIONS' }];
    currentTestContext = executionContext('testContext', ingestionUser);

    // Add new ingestionFeed
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test with auto user',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] CSV Feed to test with auto user',
      automatic_user: true,
      confidence_level: 32,
    };
    ingestionCreated = await addIngestionCsv(currentTestContext, ingestionUser, ingestionCsvInput);
  });

  afterAll(async () => {
    // Delete newly create ingestionFeed & user
    await deleteIngestionCsv(currentTestContext, ingestionUser, ingestionCreated.id);
    const createdUser = await findUserById(currentTestContext, SYSTEM_USER, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] CSV Feed to test with auto user');
    expect(createdUser.user_service_account).toBeTruthy();
    expect(createdUser.user_confidence_level?.max_confidence).toBe(32);
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });

  it('should create an automatic user and associate it to the ingestion feed', async () => {
    const ingestionCsvAddAutoUserInput: IngestionCsvAddAutoUserInput = {
      user_name: '[F] should create automatic user',
      confidence_level: 63,
    };
    const ingestionModified = await ingestionCsvAddAutoUser(currentTestContext, ingestionUser, ingestionCreated.id, ingestionCsvAddAutoUserInput);

    const createdUser = await findUserById(currentTestContext, SYSTEM_USER, ingestionModified.user_id);
    expect(createdUser.name).toBe('[F] should create automatic user');
    expect(createdUser.user_service_account).toBeTruthy();
    expect(createdUser.user_confidence_level?.max_confidence).toBe(63);
    // Delete just created user
    await adminQuery({
      query: DELETE_USER_QUERY,
      variables: { id: createdUser.id },
    });
    // Verify no longer found
    const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.user).toBeNull();
  });
});
