import { afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { getRules, RULES_DECLARATION } from '../../../../../src/domain/rules';
import { isModuleActivated } from '../../../../../src/database/cluster-module';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';

// The imports here never switch a rule: an activation would scan the knowledge base of the other tests

const UPLOAD_MUTATION = gql`mutation ConfigPresetRuleEngineUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetRuleEngineImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status reason } }
  }
`;
const EXPORT_MUTATION = gql`
  mutation ConfigPresetRuleEngineExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }
`;

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const uploadZip = async (content: Buffer) => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const importData = async (fileId: string, dryRun = false) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections: [{ type: 'ruleEngine' }], dry_run: dryRun } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; reason: string | null }[];
};
const readActivations = async () => Object.fromEntries((await getRules(testContext, ADMIN_USER)).map(({ id, activated }) => [id, activated === true]));
const ruleBundle = (id: string, active: boolean) => buildZip({
  'metadata.json': metadataFile(),
  [`automation_rules/rule_engine/${id}.json`]: itemFile('automationRules.ruleEngine', id, { active }),
});

describe('Config preset import: rule engine', () => {
  afterEach(async () => {
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetRuleEngineClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('imports back the zip of the real export: every rule is already up to date', async () => {
    const before = await readActivations();
    const result = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections: [{ type: 'ruleEngine' }] } });
    const exportId = result.data?.configPresetExport.id as string;
    const zip = await readStream(await downloadFile(exportId));
    await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });

    const fileId = await uploadZip(zip);
    const expected = RULES_DECLARATION.map(({ id }) => ({ type: 'ruleEngine', key: id, status: 'SKIPPED', reason: 'Already up to date' }));
    const dry = await importData(fileId, true);
    expect(dry).toEqual(expected);
    expect(await importData(fileId)).toEqual(expected);
    expect(await readActivations()).toEqual(before);
  });

  it('expects on a dry run the switch of a rule and the scan it starts, and switches nothing', async () => {
    const [rule] = RULES_DECLARATION;
    const before = await readActivations();
    const active = !before[rule.id];
    const scanReason = active ? 'Activating the rule starts a scan of the knowledge base' : 'Deactivating the rule starts a scan of the knowledge base';
    const reason = (await isModuleActivated('RULE_ENGINE')) ? scanReason : null;
    const dry = await importData(await uploadZip(await ruleBundle(rule.id, active)), true);
    expect(dry).toEqual([{ type: 'ruleEngine', key: rule.id, status: 'OVERWRITTEN', reason }]);
    expect(await readActivations()).toEqual(before);
  });

  it('fails a rule this platform does not declare, without touching the others', async () => {
    const before = await readActivations();
    const results = await importData(await uploadZip(await ruleBundle('rule_of_another_version', true)));
    expect(results).toEqual([{ type: 'ruleEngine', key: 'rule_of_another_version', status: 'FAILED', reason: 'Unknown rule' }]);
    expect(await readActivations()).toEqual(before);
  });
});
