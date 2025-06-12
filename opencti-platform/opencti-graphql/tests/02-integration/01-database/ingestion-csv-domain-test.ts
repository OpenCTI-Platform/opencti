import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import { addIngestionCsv, deleteIngestionCsv } from '../../../src/modules/ingestion/ingestion-csv-domain';
import { getOrganizationIdByName, PLATFORM_ORGANIZATION } from '../../utils/testQuery';
import { IngestionAuthType, type IngestionCsvAddInput } from '../../../src/generated/graphql';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { getFakeAuthUser } from '../../utils/domainQueryHelper';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { findAll as findAllGroup } from '../../../src/domain/group';
import type { BasicGroupEntity } from '../../../src/types/store';
import { findById as findUserById } from '../../../src/domain/user';
import { executionContext } from '../../../src/utils/access';

describe('Ingestion CSV domain - create CSV Feed coverage', async () => {
  const ingestionCreatedIds: string[] = [];
  let ingestionUser: AuthUser;
  let testContext: AuthContext;

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
    const groups: BasicGroupEntity[] = await findAllGroup(testContext, ingestionUser, {
      filters: {
        mode: 'and',
        filters: [
          {
            key: ['auto_integration_assignation'],
            values: [
              'global',
            ],
          },
        ],
        filterGroups: [],
      },
      connectionFormat: false
    }) as BasicGroupEntity[];
    expect(groups.length).toBe(1);
    expect(groups[0].name).toBe('Connectors');
    expect(groups[0].auto_integration_assignation).toStrictEqual(['global']);
  });

  it('should create a CSV Feed with auto user creation works fine without platform org', async () => {
    const ingestionCsvInput: IngestionCsvAddInput = {
      authentication_type: IngestionAuthType.None,
      name: 'CSV Feed to test auto user creation without platform org',
      uri: 'http://fakefeed.invalid',
      user_id: '',
      automatic_user: true
    };
    const ingestionCreated = await addIngestionCsv(testContext, ingestionUser, ingestionCsvInput);
    expect(ingestionCreated.name).toBe('CSV Feed to test auto user creation without platform org');
    ingestionCreatedIds.push(ingestionCreated.id);
    expect(ingestionCreated.user_id).toBeDefined();

    const createdUser = await findUserById(testContext, ingestionUser, ingestionCreated.user_id);
    expect(createdUser.name).toBe('[F] CSV Feed to test auto user creation without platform org');
    expect(createdUser.user_email).toBe('CSVFeedtotestautousercreationwithoutlatformorg@opencti.invalid');
  });

  it.todo('should create a CSV Feed with auto user creation works fine with platform org', async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
    // const platformOrganizationId = await getOrganizationIdByName(PLATFORM_ORGANIZATION.name);
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
