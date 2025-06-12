import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import { addIngestionCsv, deleteIngestionCsv } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { getOrganizationIdByName, PLATFORM_ORGANIZATION } from '../../utils/testQuery';
import { IngestionAuthType, type IngestionCsvAddInput } from '../../../src/generated/graphql';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { getFakeAuthUser } from '../../utils/domainQueryHelper';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { findDefaultIngestionGroup } from '../../../src/domain/group';
import type { BasicGroupEntity } from '../../../src/types/store';
import { findById as findUserById } from '../../../src/domain/user';
import { executionContext, SYSTEM_USER } from '../../../src/utils/access';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';

describe('Ingestion CSV domain - create CSV Feed coverage', async () => {
  const ingestionCreatedIds: string[] = [];
  let ingestionUser: AuthUser;
  let testContext: AuthContext;
  let ingestionDefaultGroupId: string;

  beforeAll(async () => {
    ingestionUser = getFakeAuthUser('CsvFeedIngestionDomain');
    ingestionUser.capabilities = [{ name: 'KNOWLEDGE' }, { name: 'INGESTION_SETINGESTIONS' }];
    testContext = executionContext('testContext', ingestionUser);
  });

  afterAll(async () => {
    await enableCEAndUnSetOrganization();
    for (let i = 0; i < ingestionCreatedIds.length; i += 1) {
      await deleteIngestionCsv(testContext, ingestionUser, ingestionCreatedIds[i]);
    }
  });

  it('should default group be set to Connector on startup', async () => {
    const ingestionDefaultGroups: BasicGroupEntity[] = await findDefaultIngestionGroup(testContext, ingestionUser) as BasicGroupEntity[];
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
      confidence_level: '42'
    };
    const ingestionCreated = await addIngestionCsv(testContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('CSV Feed to test auto user creation without platform org');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBeDefined();

    const createdUser = await findUserById(testContext, SYSTEM_USER, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] CSV Feed to test auto user creation without platform org');
    expect(createdUser.user_confidence_level?.max_confidence).toBe(42);
    expect(createdUser.user_email.endsWith('@opencti.invalid'), `${createdUser.user_email} should ends with @opencti.invalid'`).toBeTruthy();
    const userInDefaultGroup: BasicGroupEntity[] = createdUser.groups.filter((group: BasicGroupEntity) => group.id === ingestionDefaultGroupId);
    expect(userInDefaultGroup[0].name).toBe('Connectors'); // just to check that user is in default ingestion group
    expect(createdUser.groups.length, 'Platform default group should not apply, only default ingestion group').toBe(1);
    expect(createdUser.organizations.length, 'There is no platform org, so user should not have an organization').toBe(0);
  });

  it('should create a CSV Feed with auto user creation works fine with platform org', async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
    const platformOrganization = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);

    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test auto user creation with platform org',
      uri: 'http://fakefeed.invalid',
      user_id: '[F] CSV Feed to test auto user creation with platform org',
      automatic_user: true,
      confidence_level: '81'
    };
    const ingestionCreated = await addIngestionCsv(testContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('CSV Feed to test auto user creation with platform org');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBeDefined();

    const createdUser = await findUserById(testContext, SYSTEM_USER, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] CSV Feed to test auto user creation with platform org');
    expect(createdUser.user_confidence_level?.max_confidence).toBe(81);
    expect(createdUser.user_email.endsWith('@opencti.invalid'), `${createdUser.user_email} should ends with @opencti.invalid'`).toBeTruthy();
    const userInDefaultGroup: BasicGroupEntity[] = createdUser.groups.filter((group: BasicGroupEntity) => group.id === ingestionDefaultGroupId);
    expect(userInDefaultGroup[0].name).toBe('Connectors'); // just to check that user is in default ingestion group
    expect(createdUser.groups.length, 'Platform default group should not apply, only default ingestion group').toBe(1);

    const userOrganizations: BasicGroupEntity[] = createdUser.groups.filter((org: BasicStoreEntityOrganization) => org.id === platformOrganization.id);
    expect(userOrganizations.length, 'There is one platform org, so user should have one organization').toBe(1);
  });

  it.todo('should create a CSV Feed with System user works fine', async () => {

  });

  it.todo('should create a CSV Feed with existing user works fine', async () => {

  });

  it.todo('should create a CSV Feed with a strange name works fine', async () => {
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'MyFééd @ Testing @mail.fr 🌈🍅 - CSVフィードの作成',
      uri: 'http://fakefeed.invalid',
      user_id: '',
      automatic_user: true
    };
  });

  it.todo('should create a CSV Feed with auto user creation be refused when no default group', async () => {
    // remove default group in config

    // Create feed

    // put back default group
  });
});
