import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { getClientBase } from '../../../../../src/database/redis';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../../utils/testQuery';
import * as enterpriseEdition from '../../../../../src/enterprise-edition/ee';
import { internalLoadById } from '../../../../../src/database/middleware-loader';
import type { BasicStoreObject } from '../../../../../src/types/store';
import { CONFIG_PRESET_FAMILIES, exportConfigPresetItem } from '../../../../../src/modules/configPreset/configPreset-registry';
import { playbookAddFromImport, playbookDelete } from '../../../../../src/modules/playbook/playbook-domain';
import { findPlaybooks, RUNNING_PLAYBOOK_REASON } from '../../../../../src/modules/playbook/playbook-import';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN } from '../../../../../src/schema/identifier';

const PREVIEW_MUTATION = gql`
  mutation ConfigPresetPlaybooksPreview($file: Upload!, $type: ID!) {
    configPresetPartialImportPreview(file: $file, type: $type) { default_mode type { key modes items { key label exists conflict } } }
  }
`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetPlaybooksImport($file: Upload!, $type: ID!, $items: [ID!]!, $item_modes: [ConfigPresetItemModeInput!]) {
    configPresetPartialImport(file: $file, type: $type, items: $items, item_modes: $item_modes) { results { key status reason label } }
  }
`;

const UPLOAD_MUTATION = gql`mutation ConfigPresetPlaybooksUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const WIZARD_PREVIEW_QUERY = gql`
  query ConfigPresetPlaybooksWizardPreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) { types { key items { key exists conflict } } }
  }
`;

const NAME = 'Config preset playbook';
const MISSING_ORGANIZATION_ID = '5e0a4c3b-7d8f-4a9b-8c1d-2e3f4a5b6c7d';

const node = (id: string, componentId: string, configuration: object) => ({
  id,
  name: id,
  position: { x: 0, y: 0 },
  component_id: componentId,
  configuration: JSON.stringify(configuration),
});

const definitionOf = (memberId: string, markingId: string) => JSON.stringify({
  nodes: [
    node('start', 'PLAYBOOK_INTERNAL_DATA_STREAM', { create: true, filters: JSON.stringify({ mode: 'and', filters: [{ key: ['objectMarking'], values: [markingId] }], filterGroups: [] }) }),
    node('notify', 'PLAYBOOK_NOTIFIER_COMPONENT', { notifiers: [], authorized_members: [{ label: 'editor', value: memberId }] }),
  ],
  links: [{ id: 'link', from: { port: 'out', id: 'start' }, to: { id: 'notify' } }],
});

const zipUpload = async (files: Record<string, string>) => createUploadFromBuffer(await buildZip(files), 'bundle.zip');
const playbookBundle = (configurations: Record<string, Record<string, unknown>>) => ({
  'metadata.json': metadataFile(),
  ...Object.fromEntries(Object.entries(configurations).map(([id, configuration]) => [`automation_rules/playbooks/${id}.json`, itemFile('automationRules.playbooks', id, configuration)])),
});
const partialImport = async (files: Record<string, string>, items: string[], itemModes?: unknown[]) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file: await zipUpload(files), type: 'playbooks', items, item_modes: itemModes } });
  expect(errors).toBeUndefined();
  return data?.configPresetPartialImport.results as { key: string; status: string; reason: string | null; label: string }[];
};
const playbooksNamed = async (name: string) => (await findPlaybooks(testContext, ADMIN_USER)).filter((playbook) => playbook.name.startsWith(name));

describe('Config preset import: playbooks', () => {
  let editorId: string;
  let greenId: string;

  beforeEach(async () => {
    vi.spyOn(enterpriseEdition, 'isEnterpriseEditionUpToDate').mockResolvedValue(true);
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue(undefined as never);
    editorId = (await internalLoadById<BasicStoreObject>(testContext, ADMIN_USER, USER_EDITOR.id)).internal_id;
    greenId = (await internalLoadById<BasicStoreObject>(testContext, ADMIN_USER, MARKING_TLP_GREEN)).internal_id;
  });

  afterEach(async () => {
    const playbooks = await playbooksNamed(NAME);
    for (let i = 0; i < playbooks.length; i += 1) {
      await playbookDelete(testContext, ADMIN_USER, playbooks[i].id);
    }
    vi.restoreAllMocks();
    await queryAsAdmin({ query: gql`mutation ConfigPresetPlaybooksClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
  });

  it('exports the definition with its users by standard id, then imports it back as up to date, and as a stopped copy', async () => {
    const definition = definitionOf(editorId, greenId);
    await playbookAddFromImport(testContext, ADMIN_USER, { name: NAME, description: 'Exported', playbook_start: 'start', playbook_definition: definition, playbook_running: true });
    const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'playbooks')!;
    const [item] = await family.resolveItems(testContext, ADMIN_USER, [NAME], []);
    const exported = await exportConfigPresetItem(testContext, ADMIN_USER, family, item);
    expect(exported).toMatchObject({ type: 'automationRules.playbooks', id: NAME, configuration: { name: NAME, description: 'Exported', playbook_start: 'start' } });
    expect(exported.configuration).not.toHaveProperty('playbook_running');
    const exportedDefinition = exported.configuration.playbook_definition as string;
    expect(exportedDefinition).toContain(USER_EDITOR.id);
    expect(exportedDefinition).not.toContain(editorId);
    expect(exportedDefinition).toContain(greenId);

    const bundle = playbookBundle({ [NAME]: exported.configuration });
    const { data } = await queryAsAdmin({ query: PREVIEW_MUTATION, variables: { file: await zipUpload(bundle), type: 'playbooks' } });
    expect(data?.configPresetPartialImportPreview).toMatchObject({
      default_mode: 'COPY',
      type: { key: 'playbooks', modes: ['OVERWRITE', 'COPY'], items: [{ key: NAME, label: NAME, exists: true, conflict: true }] },
    });

    expect(await partialImport(bundle, [NAME], [{ key: NAME, mode: 'OVERWRITE' }])).toEqual([{ key: NAME, status: 'SKIPPED', reason: 'Already up to date', label: NAME }]);
    expect(await partialImport(bundle, [NAME])).toEqual([{ key: NAME, status: 'CREATED', reason: `Added as "${NAME} (1)"`, label: NAME }]);
    const copy = (await playbooksNamed(`${NAME} (1)`))[0];
    expect(copy.playbook_running).toBe(false);
    expect(copy.playbook_definition).toContain(editorId);
    expect(copy.playbook_definition).toContain(greenId);
  });

  it('overwrites a running playbook whose definition differs, which keeps running with the new definition', async () => {
    await playbookAddFromImport(testContext, ADMIN_USER, { name: NAME, description: null, playbook_start: 'start', playbook_definition: definitionOf(editorId, greenId), playbook_running: true });
    const amberId = (await internalLoadById<BasicStoreObject>(testContext, ADMIN_USER, MARKING_TLP_AMBER)).internal_id;
    const bundle = playbookBundle({ [NAME]: { name: NAME, description: null, playbook_start: 'start', playbook_definition: definitionOf(USER_EDITOR.id, amberId) } });
    expect(await partialImport(bundle, [NAME], [{ key: NAME, mode: 'OVERWRITE' }])).toEqual([{ key: NAME, status: 'OVERWRITTEN', reason: RUNNING_PLAYBOOK_REASON, label: NAME }]);
    const playbooks = await playbooksNamed(NAME);
    expect(playbooks).toHaveLength(1);
    expect(playbooks[0].playbook_running).toBe(true);
    expect(playbooks[0].playbook_definition).toContain(amberId);
    expect(playbooks[0].playbook_definition).not.toContain(greenId);
    expect(playbooks[0].playbook_definition).toContain(editorId);
  });

  it('imports a playbook whose references the platform does not have, stopped, and reports them', async () => {
    const definition = JSON.parse(definitionOf('user--00000000-0000-5000-8000-000000000000', MISSING_ORGANIZATION_ID));
    const bundle = playbookBundle({ [NAME]: { name: NAME, description: null, playbook_start: 'start', playbook_definition: JSON.stringify(definition) } });
    expect(await partialImport(bundle, [NAME], [{ key: NAME, mode: 'OVERWRITE' }])).toEqual([{
      key: NAME,
      status: 'CREATED',
      reason: `Users not found: editor\nReferences not found: ${MISSING_ORGANIZATION_ID}`,
      label: NAME,
    }]);
    const [created] = await playbooksNamed(NAME);
    expect(created.playbook_running).toBe(false);
    expect(created.playbook_definition).toContain(MISSING_ORGANIZATION_ID);
    const notify = JSON.parse(created.playbook_definition).nodes.find(({ id }: { id: string }) => id === 'notify');
    expect(JSON.parse(notify.configuration).authorized_members).toEqual([]);
  });

  it('offers a choice for a playbook of the bundle whose name an earlier one takes, so that it can be imported as a copy', async () => {
    const configuration = { name: NAME, description: null, playbook_start: 'start', playbook_definition: definitionOf(editorId, greenId) };
    const bundle = playbookBundle({ [NAME]: configuration, [`${NAME} (1)`]: configuration });
    const upload = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: await zipUpload(bundle) } });
    const preview = await queryAsAdminWithSuccess({ query: WIZARD_PREVIEW_QUERY, variables: { file_id: upload.data?.configPresetImportUpload.id } });
    const playbooks = preview.data?.configPresetImportPreview.types.find(({ key }: { key: string }) => key === 'playbooks');
    expect(playbooks.items).toEqual([
      { key: NAME, exists: false, conflict: false },
      { key: `${NAME} (1)`, exists: false, conflict: true },
    ]);
  });

  it('refuses an invalid playbook without importing it', async () => {
    const bundle = playbookBundle({ [NAME]: { name: NAME, playbook_definition: 'not a definition' } });
    const [result] = await partialImport(bundle, [NAME], [{ key: NAME, mode: 'OVERWRITE' }]);
    expect(result.status).toEqual('FAILED');
    expect(await playbooksNamed(NAME)).toEqual([]);
  });
});
