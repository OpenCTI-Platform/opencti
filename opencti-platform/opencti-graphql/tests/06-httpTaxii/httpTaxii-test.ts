import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { addIngestion, ingestionDelete, ingestionEditField } from '../../src/modules/ingestion/ingestion-taxii-collection-domain';
import { ADMIN_API_TOKEN, ADMIN_USER, testContext } from '../utils/testQuery';
import type { EditInput, IngestionTaxiiCollectionAddInput, TaxiiCollectionAddInput } from '../../src/generated/graphql';
import { getGroupEntityByName } from '../utils/domainQueryHelper';
import { getBaseUrl } from '../../src/config/conf';
import { createTaxiiCollection, taxiiCollectionDelete } from '../../src/domain/taxii';

describe('Taxii push Feed coverage', () => {
  let taxiiPushIngestionId: string;
  beforeAll(async () => {
    // Creates an Taxii push configuration
    const connectorsGroup = await getGroupEntityByName('Connectors');
    const ingestionAdd: IngestionTaxiiCollectionAddInput = {
      name: 'Taxii push test ingestion',
      authorized_members: [
        {
          id: connectorsGroup.id,
          access_right: 'view'
        }
      ]
    };
    const taxiiPushIngestion = await addIngestion(testContext, ADMIN_USER, ingestionAdd);
    expect(taxiiPushIngestion.id).toBeDefined();
    expect(taxiiPushIngestion.name).toBe('Taxii push test ingestion');
    // Start it
    const moveToRunning: EditInput[] = [{ key: 'ingestion_running', value: ['true'] }];
    await ingestionEditField(testContext, ADMIN_USER, taxiiPushIngestion.id, moveToRunning);

    taxiiPushIngestionId = taxiiPushIngestion.id;
  });

  afterAll(async () => {
    await ingestionDelete(testContext, ADMIN_USER, taxiiPushIngestionId);
  });

  const bundleObject = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--cb13d683-9173-46bc-a947-47fb7936bb52',
    objects: [
      {
        id: 'email-addr--20e5acb1-ab1e-5f49-89e1-3348fb2a4590',
        spec_version: '2.1',
        type: 'email-addr',
        extensions: {
          'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
            extension_type: 'property-extension',
            id: 'fb96642f-cdbd-4d39-8237-96077ed80677',
            type: 'Email-Addr',
            created_at: '2025-10-08T06: 17: 24.882Z',
            updated_at: '2025-10-08T06: 17: 24.882Z',
            creator_ids: [
              '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
            ]
          },
          'extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82': {
            extension_type: 'property-extension',
            score: 50
          }
        },
        value: 'patate@truc.fr'
      }
    ]
  };

  it.each([
    { contentType: 'application/taxii+json;version=2.1', name: 'TAXII content type and authentication header' },
    { contentType: 'application/taxii+json; version=2.1', name: 'TAXII content type including space and authentication header' },
    { contentType: 'application/vnd.oasis.stix+json; version=2.1', name: 'STIX content type including space and authentication header' },
  ])('should taxii post standard behavior works correctly with $name', async ({ contentType }) => {
    // Testing the content type with no space inside
    const postResponse = await fetch(`${getBaseUrl()}/taxii2/root/collections/${taxiiPushIngestionId}/objects`, {
      method: 'POST',
      headers: {
        'Content-Type': contentType,
        Authorization: `Bearer ${ADMIN_API_TOKEN}`
      },
      body: JSON.stringify(bundleObject),
    });
    const data: any = await postResponse.json();
    expect(postResponse.status).toBe(200);
    expect(data.status).toBe('pending');
    // We do not check entity from bundleObject in database since it requires the worker to process it.
  });

  it('should taxii post be refused without authenticated user', async () => {
    const result = await fetch(`${getBaseUrl()}/taxii2/root/collections/${taxiiPushIngestionId}/objects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/taxii+json;version=2.1',
      },
      body: JSON.stringify(bundleObject),
    });
    expect(result.status).toBe(401);
  });

  it('should taxii post be refused with wrong content type', async () => {
    const result = await fetch(`${getBaseUrl()}/taxii2/root/collections/${taxiiPushIngestionId}/objects`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/taxiiiii+json;version=2.1',
        Authorization: `Bearer ${ADMIN_API_TOKEN}`
      },
      body: JSON.stringify(bundleObject),
    });
    expect(result.status).toBe(400);
  });
});

describe('Should taxii collection coverage', () => {
  let taxiiCollectionPublicId: string;
  let taxiiCollectionWithAuthId: string;

  beforeAll(async () => {
    const dataSharingTaxiiPublic: TaxiiCollectionAddInput = {
      name: 'Testing coverage on Taxii collection',
      description: '',
      authorized_members: [],
      taxii_public: true,
      include_inferences: true,
      score_to_confidence: false,
      filters: JSON.stringify({
        mode: 'and',
        filters: [{ key: ['entity_type'], operator: 'eq', values: ['Indicator'], mode: 'or' }],
        filterGroups: [] })
    };
    const taxiiCollection = await createTaxiiCollection(testContext, ADMIN_USER, dataSharingTaxiiPublic);

    expect(taxiiCollection.id).toBeDefined();
    taxiiCollectionPublicId = taxiiCollection.id;
    expect(taxiiCollection.name).toBe('Testing coverage on Taxii collection');

    const dataSharingTaxiiAuth: TaxiiCollectionAddInput = {
      name: 'Testing coverage on Taxii collection not public',
      description: '',
      authorized_members: [],
      taxii_public: false,
      include_inferences: true,
      score_to_confidence: false,
      filters: JSON.stringify({
        mode: 'and',
        filters: [{ key: ['entity_type'], operator: 'eq', values: ['Malware'], mode: 'or' }],
        filterGroups: [] })
    };
    const taxiiCollectionWithauth = await createTaxiiCollection(testContext, ADMIN_USER, dataSharingTaxiiAuth);

    expect(taxiiCollectionWithauth.id).toBeDefined();
    taxiiCollectionWithAuthId = taxiiCollectionWithauth.id;
    expect(taxiiCollectionWithauth.name).toBe('Testing coverage on Taxii collection not public');
  });

  afterAll(async () => {
    await taxiiCollectionDelete(testContext, ADMIN_USER, taxiiCollectionPublicId);
    await taxiiCollectionDelete(testContext, ADMIN_USER, taxiiCollectionWithAuthId);
  });

  it('should taxii root works', async () => {
    const headers = {
      Authorization: `Bearer ${ADMIN_API_TOKEN}`
    };
    const taxiiRootResponse = await fetch(`${getBaseUrl()}/taxii2/root/`, { headers });
    const data: any = await taxiiRootResponse.json();
    expect(taxiiRootResponse.status, 'With correct authentication should works fine').toBe(200);
    expect(data.versions).toStrictEqual(['application/taxii+json;version=2.1']);
  });

  it('should public taxii collection without user works', async () => {
    const taxiiCollectionResponse = await fetch(
      `${getBaseUrl()}/taxii2/root/collections/${taxiiCollectionPublicId}/objects/`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/taxii+json;version=2.1',
          Accept: 'application/taxii+json;version=2.1'
        }
      }
    );
    expect(taxiiCollectionResponse.status).toBe(200);
    const content = await taxiiCollectionResponse.json() as { more: boolean, next: string };
    expect(content.more).toBeFalsy();
    expect(content.next.length).toBeGreaterThan(0);
  });

  it('should restricted taxii collection without user be forbidden', async () => {
    const taxiiCollectionResponse = await fetch(
      `${getBaseUrl()}/taxii2/root/collections/${taxiiCollectionWithAuthId}/objects/`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/taxii+json;version=2.1',
          Accept: 'application/taxii+json;version=2.1'
        }
      }
    );
    expect(taxiiCollectionResponse.status).toBe(401);
  });
});
