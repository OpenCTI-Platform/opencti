import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { redisClearTelemetryGauge } from '../../../../../src/database/redis';
import { TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED, TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED } from '../../../../../src/manager/telemetryManager';
import { deleteCustomView, findAllCustomViews } from '../../../../../src/modules/customView/customView-domain';
import { findCustomViewsByName } from '../../../../../src/modules/customView/customView-import';

const PREVIEW_MUTATION = gql`
  mutation ConfigPresetPartialCustomViewsPreview($file: Upload!, $type: ID!, $scope: String) {
    configPresetPartialImportPreview(file: $file, type: $type, scope: $scope) {
      default_mode
      type { key label modes items { key label exists conflict } }
    }
  }
`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetPartialCustomViewsImport($file: Upload!, $type: ID!, $items: [ID!]!, $scope: String) {
    configPresetPartialImport(file: $file, type: $type, items: $items, scope: $scope) {
      results { type key status reason label }
      counts { created overwritten skipped failed }
    }
  }
`;

const PREFIX = 'Partial import view';
const REPORT_ONE = 'customview--11111111-2222-4333-8444-555555555551';
const REPORT_TWO = 'customview--11111111-2222-4333-8444-555555555552';
const MALWARE_ONE = 'customview--11111111-2222-4333-8444-555555555553';
const viewFile = (id: string, configuration: Record<string, unknown>) => [`customization/custom_views/${id}.json`, itemFile('customization.customViews', id, configuration)] as const;
const bundleFiles = () => Object.fromEntries([
  ['metadata.json', metadataFile()],
  ['dependencies.json', '{}'],
  viewFile(REPORT_ONE, { name: `${PREFIX} report one`, target_entity_type: 'Report', description: 'First report view' }),
  viewFile(REPORT_TWO, { name: `${PREFIX} report two`, target_entity_type: 'Report' }),
  viewFile(MALWARE_ONE, { name: `${PREFIX} malware one`, target_entity_type: 'Malware' }),
]);
const zipUpload = async () => createUploadFromBuffer(await buildZip(bundleFiles()), 'bundle.zip');
const preview = async (scope?: string) => queryAsAdmin({ query: PREVIEW_MUTATION, variables: { file: await zipUpload(), type: 'customViews', scope } });
const partialImport = async (items: string[], scope?: string) => {
  return queryAsAdmin({ query: IMPORT_MUTATION, variables: { file: await zipUpload(), type: 'customViews', items, scope } });
};

describe('Config preset partial import of custom views, scoped to an entity type', () => {
  afterAll(async () => {
    const page = await findAllCustomViews(testContext, ADMIN_USER, null, { first: 500 });
    for (const { node } of page.edges.filter(({ node: view }) => view.name.startsWith(PREFIX))) {
      await deleteCustomView(testContext, ADMIN_USER, node.id);
    }
    // Creations count in the telemetry gauges that the tests of the custom view resolvers check, which run after the import tests
    await redisClearTelemetryGauge(TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED);
    await redisClearTelemetryGauge(TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED);
  });

  it('previews every custom view of the bundle without a scope, and only the ones of the entity type with it', async () => {
    const all = await preview();
    expect(all.errors).toBeUndefined();
    expect(all.data?.configPresetPartialImportPreview.default_mode).toEqual('COPY');
    expect(all.data?.configPresetPartialImportPreview.type.items.map(({ key }: { key: string }) => key).sort()).toEqual([REPORT_ONE, REPORT_TWO, MALWARE_ONE]);
    const reports = await preview('Report');
    expect(reports.errors).toBeUndefined();
    expect(reports.data?.configPresetPartialImportPreview.type).toMatchObject({ key: 'customViews', label: 'Custom views', modes: ['OVERWRITE', 'COPY'] });
    expect(reports.data?.configPresetPartialImportPreview.type.items.map(({ key, label }: { key: string; label: string }) => [key, label]).sort())
      .toEqual([[REPORT_ONE, `${PREFIX} report one (Report)`], [REPORT_TWO, `${PREFIX} report two (Report)`]]);
    // An entity type the bundle has no view of: nothing to import
    expect((await preview('Campaign')).data?.configPresetPartialImportPreview.type).toBeNull();
  });

  it('imports the selected view of the entity type, neither enabled nor the default, and nothing of the other types', async () => {
    const { data, errors } = await partialImport([REPORT_ONE], 'Report');
    expect(errors).toBeUndefined();
    expect(data?.configPresetPartialImport.counts).toEqual({ created: 1, overwritten: 0, skipped: 0, failed: 0 });
    const [imported] = await findCustomViewsByName(testContext, ADMIN_USER, 'Report', `${PREFIX} report one`);
    expect(imported).toMatchObject({ description: 'First report view', enabled: false, default: false, target_entity_type: 'Report' });
    expect(await findCustomViewsByName(testContext, ADMIN_USER, 'Report', `${PREFIX} report two`)).toEqual([]);
    expect(await findCustomViewsByName(testContext, ADMIN_USER, 'Malware', `${PREFIX} malware one`)).toEqual([]);
  });

  it('refuses the id of a view of another entity type, as an id the bundle does not have, and writes nothing', async () => {
    const { errors } = await partialImport([MALWARE_ONE], 'Report');
    expect(errors?.[0].message).toContain('Unknown configuration preset item');
    expect(await findCustomViewsByName(testContext, ADMIN_USER, 'Malware', `${PREFIX} malware one`)).toEqual([]);
  });

  it('adds a copy of a view that already exists by default, as a partial import adds to the platform', async () => {
    const preflight = await preview('Report');
    expect(preflight.data?.configPresetPartialImportPreview.type.items.find(({ key }: { key: string }) => key === REPORT_ONE)).toMatchObject({ exists: true, conflict: true });
    const { data } = await partialImport([REPORT_ONE], 'Report');
    expect(data?.configPresetPartialImport.results[0]).toMatchObject({ status: 'CREATED', reason: `Added as "${PREFIX} report one (1)"` });
    expect(await findCustomViewsByName(testContext, ADMIN_USER, 'Report', `${PREFIX} report one`)).toHaveLength(1);
    expect(await findCustomViewsByName(testContext, ADMIN_USER, 'Report', `${PREFIX} report one (1)`)).toHaveLength(1);
  });

  it('imports the views of another entity type from the screen of that type', async () => {
    const { data } = await partialImport([MALWARE_ONE], 'Malware');
    expect(data?.configPresetPartialImport.counts).toEqual({ created: 1, overwritten: 0, skipped: 0, failed: 0 });
    expect(await findCustomViewsByName(testContext, ADMIN_USER, 'Malware', `${PREFIX} malware one`)).toHaveLength(1);
  });
});
