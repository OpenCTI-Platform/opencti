import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { isEnterpriseEditionUpToDate } from '../../../../../src/enterprise-edition/ee';
import conf, { ENABLED_FEATURE_FLAGS } from '../../../../../src/config/conf';
import { synchronizeCatalogs } from '../../../../../src/modules/catalog/sync/catalog-sync-domain';
import { findConnectorManagers, findConnectors } from '../../../../../src/modules/connector/connector-repository';
import { addGroup } from '../../../../../src/domain/grant';
import { findDefaultIngestionGroups, groupDelete, groupEditField } from '../../../../../src/domain/group';
import { userDelete } from '../../../../../src/modules/user/user-domain';
import * as UserActionListener from '../../../../../src/listener/UserActionListener';
import * as enterpriseEdition from '../../../../../src/enterprise-edition/ee';
import { catalogHelper } from '../../../../utils/catalogHelper';

const UPLOAD_MUTATION = gql`mutation ConfigPresetConnectorsUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetConnectorsImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean, $credentials: [ConfigPresetItemCredentialsInput!]) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run, credentials: $credentials) { results { type key status reason } report_id }
  }
`;
const PREVIEW_QUERY = gql`
  query ConfigPresetConnectorsPreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) { types { key lockedByEnterpriseEdition group { key } items { key credentials { key required } } } }
  }
`;

const SECRET = 'connector-secret-value';
const credentials = [{ type: 'connectors', key: 'mitre', values: [{ key: 'MITRE_API_KEY', secret: SECRET }] }];
const connectorBundle = () => ({
  'metadata.json': metadataFile(),
  'integrations/connectors/mitre.json': itemFile('integrations.connectors', 'mitre', {
    name: 'MITRE',
    catalog_id: 'filigran-catalog',
    manager_contract_image: 'opencti/connector-mitre',
    confidence_level: 75,
    manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '7' }],
    required_at_import: ['MITRE_API_KEY'],
  }),
});
const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
};
const upload = async () => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(await buildZip(connectorBundle()), 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const runImport = async (fileId: string, dryRun: boolean) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections: [{ type: 'connectors' }], dry_run: dryRun, credentials } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport as { results: { type: string; key: string; status: string; reason: string | null }[]; report_id: string | null };
};
const sessionContent = async () => (await getClientBase().get(`config_preset_import_session_${ADMIN_USER.id}`)) ?? '';
const historyContent = async () => {
  const files = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
  const contents = await Promise.all(files.map(async (file) => readStream(await downloadFile(file.id))));
  return contents.join('\n');
};

describe('Config preset import: connectors', () => {
  afterEach(async () => {
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetConnectorsClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('lists the connectors under Integrations, locked without the Enterprise Edition', async () => {
    const fileId = await upload();
    const preview = (await queryAsAdminWithSuccess({ query: PREVIEW_QUERY, variables: { file_id: fileId } })).data?.configPresetImportPreview;
    const connectors = preview.types.find((type: { key: string }) => type.key === 'connectors');
    expect(connectors.group.key).toEqual('integrations');
    const isEnterpriseEdition = await isEnterpriseEditionUpToDate(testContext);
    expect(connectors.lockedByEnterpriseEdition).toEqual(!isEnterpriseEdition);
    expect(connectors.items.map(({ key }: { key: string }) => key)).toEqual(isEnterpriseEdition ? ['mitre'] : []);
  });

  it('never writes the secrets given at import in the session nor in the report', async () => {
    const fileId = await upload();
    const dry = await runImport(fileId, true);
    expect(dry.results.map(({ key }) => key)).toEqual(['mitre']);
    const real = await runImport(fileId, false);
    expect(real.results.map(({ key }) => key)).toEqual(['mitre']);
    expect(await sessionContent()).not.toContain(SECRET);
    expect(real.report_id).not.toBeNull();
    expect(await readStream(await downloadFile(real.report_id!))).not.toContain(SECRET);
  });

  describe('with a catalog and a connector manager', () => {
    const ID = 'config-preset-ipinfo';
    const REGISTER_MANAGER = gql`mutation ConfigPresetConnectorsManager($input: RegisterConnectorsManagerInput!) { registerConnectorsManager(input: $input) { id } }`;
    const DELETE_CONNECTOR = gql`mutation ConfigPresetConnectorsDelete($id: ID!) { deleteConnector(id: $id) }`;
    const previousFeatureFlags = [...ENABLED_FEATURE_FLAGS];
    const previousCatalogEndpoint = conf.get('catalog_manager:custom_catalog_refresh_endpoint_uri');
    const previousCustomCatalogs = conf.get('app:custom_catalogs');
    let ingestionGroupId: string | undefined;
    const ipinfoBundle = (parameters: { key: string; value: string }[]) => ({
      'metadata.json': metadataFile(),
      [`integrations/connectors/${ID}.json`]: itemFile('integrations.connectors', ID, {
        name: 'Config preset ipinfo',
        catalog_id: catalogHelper.getCatalogId(),
        manager_contract_image: catalogHelper.getTestSafeConnector().container_image.split(':')[0],
        confidence_level: 75,
        manager_contract_configuration: parameters,
        required_at_import: ['IPINFO_TOKEN'],
      }),
    });
    const importIpinfo = async (parameters: { key: string; value: string }[], secret: string, dryRun = false) => {
      const upload = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(await buildZip(ipinfoBundle(parameters)), 'bundle.zip') } });
      const variables = {
        file_id: upload.data?.configPresetImportUpload.id,
        selections: [{ type: 'connectors' }],
        dry_run: dryRun,
        credentials: [{ type: 'connectors', key: ID, values: [{ key: 'IPINFO_TOKEN', secret }] }],
      };
      const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables });
      expect(errors).toBeUndefined();
      return data?.configPresetImport as { results: { type: string; key: string; status: string; reason: string | null }[]; report_id: string | null };
    };
    const findIpinfo = async () => (await findConnectors(testContext, ADMIN_USER)).find(({ name }) => name === ID);
    const parameters = [{ key: 'CONNECTOR_LISTEN_PROTOCOL_API_PORT', value: '0' }, { key: 'CONNECTOR_LISTEN_PROTOCOL_API_SSL', value: 'false' }];

    beforeAll(async () => {
      if (!ENABLED_FEATURE_FLAGS.includes('DECOUPLING_VERSIONS')) {
        ENABLED_FEATURE_FLAGS.push('DECOUPLING_VERSIONS');
      }
      conf.set('app:custom_catalogs', []);
      conf.set('catalog_manager:custom_catalog_refresh_endpoint_uri', new URL('../../../../utils/opencti-manifest.json', import.meta.url).toString());
      await synchronizeCatalogs(testContext, ADMIN_USER);
      if ((await findConnectorManagers(testContext, ADMIN_USER)).length === 0) {
        const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'pkcs1', format: 'pem' }, privateKeyEncoding: { type: 'pkcs1', format: 'pem' } });
        await queryAsAdminWithSuccess({ query: REGISTER_MANAGER, variables: { input: { id: uuidv4(), name: 'Config preset manager', public_key: publicKey } } });
      }
      if ((await findDefaultIngestionGroups(testContext, ADMIN_USER)).length === 0) {
        const group = await addGroup(testContext, ADMIN_USER, { name: 'Config preset ingestion group' });
        await groupEditField(testContext, ADMIN_USER, group.id, [{ key: 'auto_integration_assignation', value: ['global'] }]);
        ingestionGroupId = group.id;
      }
    });

    afterAll(async () => {
      const connector = await findIpinfo();
      if (connector) {
        await queryAsAdmin({ query: DELETE_CONNECTOR, variables: { id: connector.id } });
        await userDelete(testContext, ADMIN_USER, connector.connector_user_id);
      }
      if (ingestionGroupId) {
        await groupDelete(testContext, ADMIN_USER, ingestionGroupId);
      }
      conf.set('catalog_manager:custom_catalog_refresh_endpoint_uri', previousCatalogEndpoint);
      conf.set('app:custom_catalogs', previousCustomCatalogs);
      ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousFeatureFlags);
    });

    it('creates then overwrites the connector with the secret given, never writing it outside the connector, where it is encrypted', async () => {
      vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
      vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined as never);
      const publishUserAction = vi.spyOn(UserActionListener, 'publishUserAction');
      try {
        expect((await importIpinfo(parameters, SECRET, true)).results).toMatchObject([{ key: ID, status: 'CREATED' }]);
        const created = await importIpinfo(parameters, SECRET);
        expect(created.results).toMatchObject([{ key: ID, status: 'CREATED' }]);
        const connector = (await findIpinfo())!;
        expect(connector.manager_contract_configuration?.find(({ key }) => key === 'IPINFO_TOKEN')).toMatchObject({ encrypted: true });
        expect(JSON.stringify(connector.manager_contract_configuration)).not.toContain(SECRET);

        const otherSecret = `${SECRET}-rotated`;
        const overwritten = await importIpinfo([...parameters, { key: 'ENRICHMENT_MAX_TLP', value: 'TLP:RED' }], otherSecret);
        expect(overwritten.results).toMatchObject([{ key: ID, status: 'OVERWRITTEN' }]);
        const updated = (await findIpinfo())!;
        expect(updated.manager_contract_configuration?.find(({ key }) => key === 'ENRICHMENT_MAX_TLP')?.value).toEqual('TLP:RED');
        expect(JSON.stringify(updated.manager_contract_configuration)).not.toContain(otherSecret);

        for (const report of [created, overwritten]) {
          expect(await readStream(await downloadFile(report.report_id!))).not.toMatch(new RegExp(SECRET));
        }
        expect(await sessionContent()).not.toContain(SECRET);
        expect(await historyContent()).not.toContain(SECRET);
        expect(JSON.stringify(publishUserAction.mock.calls)).not.toContain(SECRET);
        expect(publishUserAction).toHaveBeenCalled();
      } finally {
        vi.restoreAllMocks();
      }
    });
  });
});
