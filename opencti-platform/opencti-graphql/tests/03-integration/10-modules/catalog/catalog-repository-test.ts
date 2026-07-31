import { afterAll, describe, expect, it } from 'vitest';
import { deleteElementById } from '../../../../src/database/middleware';
import {
  findContractFromESByContainerImage,
  findContractFromESBySlug,
  findCatalogFromES,
  findContractBySlugAndVersion,
  findLatestContractBySlug,
  upsertCatalogContract,
} from '../../../../src/modules/catalog/catalog-repository';
import { ENTITY_TYPE_CATALOG_CONTRACT } from '../../../../src/modules/catalog/catalog-entity-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

const createdContractIds: string[] = [];

const trackContract = (id?: string) => {
  if (id) createdContractIds.push(id);
};

afterAll(async () => {
  for (const id of createdContractIds) {
    await deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_CATALOG_CONTRACT);
  }
});

describe('catalog-repository integration (no mocks)', () => {
  it('findLatestContractBySlug returns highest version for same slug', async () => {
    const slug = `it-catalog-latest-${Date.now()}`;

    const first = await upsertCatalogContract(testContext, ADMIN_USER, {
      catalog_id: 'integration-test-catalog',
      slug,
      version: '1.0.0',
      title: 'IT Contract A',
      description: 'Integration test contract A',
      use_cases: [],
      verified: true,
      playbook_supported: false,
      manager_supported: false,
      image: 'opencti/connector-it-a',
      config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
      last_synced_at: new Date().toISOString(),
    });
    trackContract(first.id);

    const second = await upsertCatalogContract(testContext, ADMIN_USER, {
      catalog_id: 'integration-test-catalog',
      slug,
      version: '2025.10.1',
      title: 'IT Contract B',
      description: 'Integration test contract B',
      use_cases: [],
      verified: true,
      playbook_supported: true,
      manager_supported: true,
      image: 'opencti/connector-it-b',
      config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
      last_synced_at: new Date().toISOString(),
    });
    trackContract(second.id);

    const latest = await findLatestContractBySlug(testContext, ADMIN_USER, slug);
    expect(latest).toBeDefined();
    expect(latest?.version).toBe('2025.10.1');

    const previous = await findContractBySlugAndVersion(testContext, ADMIN_USER, slug, '1.0.0');
    expect(previous).toBeDefined();
  });

  it('findCatalogFromES keeps manager_supported in serialized contracts', async () => {
    const slug = `it-catalog-es-${Date.now()}`;

    const created = await upsertCatalogContract(testContext, ADMIN_USER, {
      catalog_id: 'integration-test-catalog',
      slug,
      version: '2.0.0',
      title: `IT Catalog ${slug}`,
      description: 'Integration test catalog for ES mapping',
      use_cases: ['Testing'],
      verified: false,
      playbook_supported: true,
      manager_supported: true,
      image: 'opencti/connector-it-es',
      type: 'INTERNAL_ENRICHMENT',
      support_version: '1.0.0',
      max_confidence_level: 42,
      config_schema: JSON.stringify({
        type: 'object',
        properties: {
          OPENCTI_TOKEN: { type: 'string' },
          CUSTOM_FIELD: { type: 'string' },
        },
        required: ['CUSTOM_FIELD'],
      }),
      last_synced_at: new Date().toISOString(),
    });
    trackContract(created.id);

    const catalogs = await findCatalogFromES(testContext, ADMIN_USER);
    const targetCatalog = catalogs.find((catalog) => catalog.name === `IT Catalog ${slug}`);

    expect(targetCatalog).toBeDefined();
    expect(targetCatalog?.contracts).toHaveLength(1);

    const parsed = JSON.parse(targetCatalog!.contracts[0]);
    expect(parsed.slug).toBe(slug);
    expect(parsed.manager_supported).toBe(true);
    expect(parsed.container_image).toBe('opencti/connector-it-es');
  });

  it('findContractFromESBySlug returns serialized latest contract payload', async () => {
    const slug = `it-catalog-contract-slug-${Date.now()}`;

    const created = await upsertCatalogContract(testContext, ADMIN_USER, {
      catalog_id: 'integration-test-catalog',
      slug,
      version: '3.0.0',
      title: `IT Contract ${slug}`,
      description: 'Integration test direct slug contract lookup',
      use_cases: ['Testing'],
      verified: true,
      playbook_supported: false,
      manager_supported: true,
      image: `opencti/connector-${slug}`,
      type: 'INTERNAL_ENRICHMENT',
      config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
      last_synced_at: new Date().toISOString(),
    });
    trackContract(created.id);

    const contractData = await findContractFromESBySlug(testContext, ADMIN_USER, slug);

    expect(contractData).toBeDefined();
    expect(contractData?.catalog_id).toBe('integration-test-catalog');

    const parsed = JSON.parse(contractData!.contract);
    expect(parsed.slug).toBe(slug);
    expect(parsed.container_image).toBe(`opencti/connector-${slug}`);
  });

  it('findContractFromESByContainerImage returns serialized latest contract payload', async () => {
    const slug = `it-catalog-contract-image-${Date.now()}`;
    const image = `opencti/connector-${slug}`;

    const older = await upsertCatalogContract(testContext, ADMIN_USER, {
      catalog_id: 'integration-test-catalog',
      slug,
      version: '1.0.0',
      title: `IT Contract ${slug} old`,
      description: 'Integration test direct image contract lookup old version',
      use_cases: ['Testing'],
      verified: true,
      playbook_supported: false,
      manager_supported: true,
      image,
      type: 'INTERNAL_ENRICHMENT',
      config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
      last_synced_at: new Date().toISOString(),
    });
    trackContract(older.id);

    const latest = await upsertCatalogContract(testContext, ADMIN_USER, {
      catalog_id: 'integration-test-catalog',
      slug,
      version: '2.2.0',
      title: `IT Contract ${slug} latest`,
      description: 'Integration test direct image contract lookup latest version',
      use_cases: ['Testing'],
      verified: true,
      playbook_supported: false,
      manager_supported: true,
      image,
      type: 'INTERNAL_ENRICHMENT',
      config_schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
      last_synced_at: new Date().toISOString(),
    });
    trackContract(latest.id);

    const contractData = await findContractFromESByContainerImage(testContext, ADMIN_USER, image);

    expect(contractData).toBeDefined();
    expect(contractData?.catalog_id).toBe('integration-test-catalog');

    const parsed = JSON.parse(contractData!.contract);
    expect(parsed.slug).toBe(slug);
    expect(parsed.container_version).toBe('2.2.0');
  });
});
