import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { synchronizeCatalogs } from '../../../../src/modules/catalog/sync/catalog-sync-domain';
import conf, { ENABLED_FEATURE_FLAGS, FEATURE_FLAG_ALL } from '../../../../src/config/conf';

const LIST_CATALOGS_QUERY = gql`
  query Catalogs {
    catalogs {
      id
      name
      description
      contracts
    }
  }
`;

const GET_CATALOG_BY_ID_QUERY = gql`
  query CatalogById($id: String!) {
    catalog(id: $id) {
      id
      name
      description
      contracts
    }
  }
`;

const GET_CONTRACT_BY_SLUG_QUERY = gql`
  query ContractBySlug($slug: String!) {
    contract(slug: $slug) {
      catalog_id
      contract
    }
  }
`;

const assertContractShape = (contract: any) => {
  expect(contract.title).toEqual(expect.any(String));
  expect(contract.slug).toEqual(expect.any(String));
  expect(contract.description).toEqual(expect.any(String));
  expect(contract.short_description).toEqual(expect.any(String));
  expect(contract.use_cases).toEqual(expect.any(Array));
  expect(contract.verified).toEqual(expect.any(Boolean));
  expect(contract.playbook_supported).toEqual(expect.any(Boolean));
  expect(contract.max_confidence_level).toEqual(expect.any(Number));
  expect(contract.source_code).toEqual(expect.any(String));
  expect(contract.manager_supported).toEqual(expect.any(Boolean));
  expect(contract.container_version).toEqual(expect.any(String));
  expect(contract.container_image).toEqual(expect.any(String));
  expect(contract.container_type).toEqual(expect.any(String));
  expect(contract.config_schema).toEqual(expect.any(Object));
  expect(contract.logo === null || typeof contract.logo === 'string').toBe(true);
  expect(contract.last_verified_date === null || typeof contract.last_verified_date === 'string').toBe(true);
  expect(contract.support_version === null || typeof contract.support_version === 'string').toBe(true);
  expect(contract.subscription_link === null || typeof contract.subscription_link === 'string').toBe(true);
  expect(contract.config_schema).toMatchObject({
    type: expect.any(String),
    properties: expect.any(Object),
    required: expect.any(Array),
    additionalProperties: expect.any(Boolean),
  });
};

describe('Catalog resolver integration', () => {
  const v0TemplatePath = fileURLToPath(new URL('./fixture/integration-catalog-v0.json', import.meta.url));
  const v1TemplatePath = fileURLToPath(new URL('./fixture/integration-catalog-v1.json', import.meta.url));
  let v0CatalogUri = '';
  let v1CatalogUri = '';
  let catalogV0Id = '';
  let catalogV1Id = '';
  let catalogV0Slug = '';
  let catalogV1Slug = '';
  let tempFixtureDir = '';
  const previousEnabledFeatureFlags = [...ENABLED_FEATURE_FLAGS];
  const previousCustomCatalogRefreshEndpoint = conf.get('catalog_manager:custom_catalog_refresh_endpoint_uri');
  const previousCustomCatalogs = conf.get('app:custom_catalogs');
  const runtimeKeys = ['OPENCTI_TOKEN', 'OPENCTI_URL', 'CONNECTOR_TYPE', 'CONNECTOR_RUN_AND_TERMINATE'];

  const assertCatalogEndpoints = async (expectedCatalogId: string, expectedSlug: string, customCatalogUri: string) => {
    conf.set('catalog_manager:custom_catalog_refresh_endpoint_uri', customCatalogUri);
    await synchronizeCatalogs(testContext, ADMIN_USER);

    const catalogsResult = await queryAsAdminWithSuccess({
      query: LIST_CATALOGS_QUERY,
      variables: {},
    });
    const catalogs = catalogsResult.data?.catalogs ?? [];
    const expectedCatalog = catalogs.find((catalog: any) => catalog.id === expectedCatalogId);
    expect(expectedCatalog).toBeDefined();

    for (const catalog of catalogs) {
      expect(catalog).toMatchObject({
        id: expect.any(String),
        name: expect.any(String),
        description: expect.any(String),
        contracts: expect.any(Array),
      });
      const contracts = catalog.contracts.map((raw: string) => JSON.parse(raw));
      const slugs = contracts.map((contract: { slug: string }) => contract.slug);
      expect(new Set(slugs).size).toEqual(slugs.length);
      contracts.forEach((contract: any) => {
        assertContractShape(contract);
        runtimeKeys.forEach((runtimeKey) => {
          expect(contract.config_schema.properties[runtimeKey]).toBeUndefined();
        });
      });
    }

    const byIdResult = await queryAsAdminWithSuccess({
      query: GET_CATALOG_BY_ID_QUERY,
      variables: { id: expectedCatalogId },
    });
    const byIdCatalog = byIdResult.data?.catalog;
    expect(byIdCatalog).toMatchObject({
      id: expectedCatalogId,
      name: expect.any(String),
      description: expect.any(String),
      contracts: expect.any(Array),
    });
    expect(byIdCatalog.contracts.length).toBeGreaterThan(0);
    const byIdContract = JSON.parse(byIdCatalog.contracts[0]);
    assertContractShape(byIdContract);
    runtimeKeys.forEach((runtimeKey) => {
      expect(byIdContract.config_schema.properties[runtimeKey]).toBeUndefined();
    });

    const bySlugResult = await queryAsAdminWithSuccess({
      query: GET_CONTRACT_BY_SLUG_QUERY,
      variables: { slug: expectedSlug },
    });
    const bySlugPayload = bySlugResult.data?.contract;
    expect(bySlugPayload).toMatchObject({
      catalog_id: expectedCatalogId,
      contract: expect.any(String),
    });
    const bySlugContract = JSON.parse(bySlugPayload.contract);
    assertContractShape(bySlugContract);
    expect(bySlugContract.slug).toEqual(expectedSlug);
    runtimeKeys.forEach((runtimeKey) => {
      expect(bySlugContract.config_schema.properties[runtimeKey]).toBeUndefined();
    });
  };

  beforeAll(async () => {
    const runSuffix = uuidv4().slice(0, 8);
    tempFixtureDir = await mkdtemp(join(tmpdir(), 'opencti-catalog-integration-'));
    const v0Fixture = JSON.parse(await readFile(v0TemplatePath, 'utf8'));
    const v1Fixture = JSON.parse(await readFile(v1TemplatePath, 'utf8'));

    catalogV0Id = `integration-catalog-v0-${runSuffix}`;
    catalogV1Id = `integration-catalog-v1-${runSuffix}`;
    catalogV0Slug = `integration-v0-connector-${runSuffix}`;
    catalogV1Slug = `integration-v1-connector-${runSuffix}`;

    v0Fixture.id = catalogV0Id;
    v0Fixture.contracts[0].slug = catalogV0Slug;
    v1Fixture.id = catalogV1Id;
    v1Fixture.contracts[0].slug = catalogV1Slug;
    v1Fixture.contracts[0].id = `${catalogV1Slug}-${v1Fixture.contracts[0].version}`;

    const v0TempPath = join(tempFixtureDir, 'integration-catalog-v0.json');
    const v1TempPath = join(tempFixtureDir, 'integration-catalog-v1.json');
    await writeFile(v0TempPath, JSON.stringify(v0Fixture), 'utf8');
    await writeFile(v1TempPath, JSON.stringify(v1Fixture), 'utf8');
    v0CatalogUri = pathToFileURL(v0TempPath).toString();
    v1CatalogUri = pathToFileURL(v1TempPath).toString();

    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    ENABLED_FEATURE_FLAGS.push(...previousEnabledFeatureFlags.filter((flag) => flag !== FEATURE_FLAG_ALL));
    if (!ENABLED_FEATURE_FLAGS.includes('DECOUPLING_VERSIONS')) {
      ENABLED_FEATURE_FLAGS.push('DECOUPLING_VERSIONS');
    }
    conf.set('app:custom_catalogs', []);
  });

  afterAll(async () => {
    conf.set('catalog_manager:custom_catalog_refresh_endpoint_uri', previousCustomCatalogRefreshEndpoint);
    conf.set('app:custom_catalogs', previousCustomCatalogs);
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousEnabledFeatureFlags);
    if (tempFixtureDir) {
      await rm(tempFixtureDir, { recursive: true, force: true });
    }
  });

  it('should expose expected endpoint shapes with a custom V0 catalog source', async () => {
    await assertCatalogEndpoints(catalogV0Id, catalogV0Slug, v0CatalogUri);
  });

  it('should expose expected endpoint shapes with a custom V1 catalog source', async () => {
    await assertCatalogEndpoints(catalogV1Id, catalogV1Slug, v1CatalogUri);
  });
});
