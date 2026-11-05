import { afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { isEnterpriseEditionUpToDate } from '../../../../../src/enterprise-edition/ee';

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
});
