import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { addIngestion, findAllRssIngestion, ingestionDelete } from '../../../../../src/modules/ingestion/ingestion-rss-domain';
import { findAllTaxiiIngestion, ingestionTaxiiAdd, ingestionTaxiiDelete } from '../../../../../src/modules/ingestion/ingestion-taxii-domain';
import { decryptIngestionCredential } from '../../../../../src/modules/ingestion/ingestion-common';
import { CONFIG_PRESET_FAMILIES, exportConfigPresetItem } from '../../../../../src/modules/configPreset/configPreset-registry';
import { IngestionAuthType, TaxiiVersion } from '../../../../../src/generated/graphql';

const UPLOAD_MUTATION = gql`mutation ConfigPresetFeedsUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetFeedsImport(
    $file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean,
    $credentials: [ConfigPresetItemCredentialsInput!], $service_accounts: [ConfigPresetItemServiceAccountInput!]
  ) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run, credentials: $credentials, service_accounts: $service_accounts) {
      results { type key status reason }
      report_id
    }
  }
`;
const PREVIEW_QUERY = gql`
  query ConfigPresetFeedsPreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) { types { key group { key } items { key credentials { key required stored secret } } } }
  }
`;

const SECRET = 'feed-secret-value';
const RSS_NAME = 'Config preset RSS feed';
const TAXII_NAME = 'Config preset TAXII feed';
const COPY_NAME = `${TAXII_NAME} (1)`;
const family = (id: string) => CONFIG_PRESET_FAMILIES.find((candidate) => candidate.id === id)!;
const exportItem = async (familyId: string, id: string) => {
  const [item] = await family(familyId).resolveItems(testContext, ADMIN_USER, [id], []);
  return exportConfigPresetItem(testContext, ADMIN_USER, family(familyId), item);
};
const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
};
const sessionContent = async () => (await getClientBase().get(`config_preset_import_session_${ADMIN_USER.id}`)) ?? '';

describe('Config preset: feeds', () => {
  let rssFeedId: string;
  let taxiiFeedId: string;
  let bundle: Record<string, string>;

  beforeAll(async () => {
    rssFeedId = (await addIngestion(testContext, ADMIN_USER, {
      name: RSS_NAME,
      uri: 'https://news.example.com/rss',
      user_id: ADMIN_USER.id,
      report_types: ['threat-report'],
      ingestion_running: true,
    })).id;
    taxiiFeedId = (await ingestionTaxiiAdd(testContext, ADMIN_USER, {
      name: TAXII_NAME,
      uri: 'https://taxii.example.com',
      collection: 'collection-id',
      version: TaxiiVersion.V21,
      authentication_type: IngestionAuthType.Basic,
      authentication_value: `analyst:${SECRET}`,
      user_id: ADMIN_USER.id,
    })).id;
    const rssFile = await exportItem('rssFeeds', RSS_NAME);
    const taxiiFile = await exportItem('taxiiFeeds', TAXII_NAME);
    bundle = {
      'metadata.json': metadataFile(),
      [`integrations/rss_feeds/${RSS_NAME}.json`]: itemFile(rssFile.type, rssFile.id, rssFile.configuration),
      [`integrations/taxii_feeds/${TAXII_NAME}.json`]: itemFile(taxiiFile.type, taxiiFile.id, taxiiFile.configuration),
    };
  });

  afterEach(async () => {
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetFeedsClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  afterAll(async () => {
    const rssFeeds = (await findAllRssIngestion(testContext, ADMIN_USER)).filter(({ name }) => name.startsWith(RSS_NAME));
    for (let i = 0; i < rssFeeds.length; i += 1) {
      await ingestionDelete(testContext, ADMIN_USER, rssFeeds[i].id);
    }
    const taxiiFeeds = (await findAllTaxiiIngestion(testContext, ADMIN_USER)).filter(({ name }) => name.startsWith(TAXII_NAME));
    for (let i = 0; i < taxiiFeeds.length; i += 1) {
      await ingestionTaxiiDelete(testContext, ADMIN_USER, taxiiFeeds[i].id);
    }
  });

  const upload = async () => {
    const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(await buildZip(bundle), 'bundle.zip') } });
    return result.data?.configPresetImportUpload.id as string;
  };
  const runImport = async (fileId: string, dryRun: boolean, variables: Record<string, unknown> = {}) => {
    const { data, errors } = await queryAsAdmin({
      query: IMPORT_MUTATION,
      variables: { file_id: fileId, selections: [{ type: 'rssFeeds' }, { type: 'taxiiFeeds' }], dry_run: dryRun, ...variables },
    });
    expect(errors).toBeUndefined();
    return data?.configPresetImport as { results: { type: string; key: string; status: string; reason: string | null }[]; report_id: string | null };
  };

  it('exports the feeds by name, without their credentials, user nor running state', async () => {
    const taxiiFile = await exportItem('taxiiFeeds', TAXII_NAME);
    expect(taxiiFile).toMatchObject({ type: 'integrations.taxiiFeeds', id: TAXII_NAME, configuration: { name: TAXII_NAME, authentication_type: 'basic' } });
    const serialized = JSON.stringify([taxiiFile, await exportItem('rssFeeds', RSS_NAME)]);
    expect(serialized).not.toContain(SECRET);
    expect(serialized).not.toMatch(/authentication_value|user_id|ingestion_running|analyst/);
  });

  it('lists the feeds under Integrations, the stored credentials of the feed it overwrites included', async () => {
    const fileId = await upload();
    const preview = (await queryAsAdminWithSuccess({ query: PREVIEW_QUERY, variables: { file_id: fileId } })).data?.configPresetImportPreview;
    const taxii = preview.types.find((type: { key: string }) => type.key === 'taxiiFeeds');
    expect(taxii.group.key).toEqual('integrations');
    expect(taxii.items).toEqual([{
      key: TAXII_NAME,
      credentials: [
        { key: 'username', required: true, stored: true, secret: false },
        { key: 'password', required: true, stored: true, secret: true },
      ],
    }]);
  });

  it('skips the feeds already up to date', async () => {
    const { results } = await runImport(await upload(), true);
    expect(results.map(({ key, status }) => [key, status])).toEqual([[RSS_NAME, 'SKIPPED'], [TAXII_NAME, 'SKIPPED']]);
  });

  it('adds a stopped copy with the credentials given at import, never written in the session nor in the report', async () => {
    const fileId = await upload();
    const variables = {
      selections: [{ type: 'taxiiFeeds', item_modes: [{ key: TAXII_NAME, mode: 'COPY' }] }],
      credentials: [{ type: 'taxiiFeeds', key: TAXII_NAME, values: [{ key: 'username', secret: 'partner' }, { key: 'password', secret: SECRET }] }],
      service_accounts: [{ type: 'taxiiFeeds', key: TAXII_NAME, user_id: ADMIN_USER.id }],
    };
    const dry = await runImport(fileId, true, variables);
    expect(dry.results).toEqual([{ type: 'taxiiFeeds', key: TAXII_NAME, status: 'CREATED', reason: `Added as "${COPY_NAME}"` }]);
    const real = await runImport(fileId, false, variables);
    expect(real.results.map(({ status }) => status)).toEqual(['CREATED']);
    const copy = (await findAllTaxiiIngestion(testContext, ADMIN_USER)).find(({ name }) => name === COPY_NAME)!;
    expect(copy).toMatchObject({ ingestion_running: false, user_id: ADMIN_USER.id, collection: 'collection-id' });
    expect(copy.authentication_value).not.toContain(SECRET);
    expect(await decryptIngestionCredential(copy.authentication_value)).toEqual(`partner:${SECRET}`);
    expect(await sessionContent()).not.toContain(SECRET);
    expect(await readStream(await downloadFile(real.report_id!))).not.toContain(SECRET);
    const original = (await findAllTaxiiIngestion(testContext, ADMIN_USER)).find(({ id }) => id === taxiiFeedId)!;
    expect(await decryptIngestionCredential(original.authentication_value)).toEqual(`analyst:${SECRET}`);
    expect(rssFeedId).toBeDefined();
  });
});
