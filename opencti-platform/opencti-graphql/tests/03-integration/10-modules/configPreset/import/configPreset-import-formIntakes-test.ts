import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { findById as findGroupById } from '../../../../../src/domain/group';
import { findById as findMarkingById } from '../../../../../src/domain/markingDefinition';
import { findAllLabels } from '../../../../../src/domain/label';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { markingStandardId } from '../../../../../src/modules/markingDefinition/marking-import';
import { groupStandardId } from '../../../../../src/modules/user/group-import';
import { addForm, findAllForms, formDelete, formEditField } from '../../../../../src/modules/form/form-domain';
import type { BasicStoreEntityForm, FormSchemaDefinition } from '../../../../../src/modules/form/form-types';
import type { BasicStoreEntity } from '../../../../../src/types/store';

const UPLOAD_MUTATION = gql`mutation ConfigPresetFormIntakesUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetFormIntakesImport($file_id: ID!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { type key status reason } }
  }
`;
const EXPORT_MUTATION = gql`
  mutation ConfigPresetFormIntakesExport($selections: [ConfigPresetSelectionInput!]!) { configPresetExport(selections: $selections) { id } }
`;

// Every form this test writes starts with this prefix, so that it can be deleted afterwards
const PREFIX = 'Config preset intake';
const FORM_NAME = `${PREFIX} round trip`;
// The marking, the label and the group of the platform, not new ones: creating one would change the counts of the streams other tests check
const TLP_AMBER = markingStandardId('TLP', 'TLP:AMBER');
const GROUP_NAME = 'Default';

type Entity = BasicStoreEntity & { name?: string; value?: string };
let marking: Entity;
let label: Entity;
let group: Entity;

const readStream = async (stream: unknown) => {
  const chunks: Buffer[] = [];
  for await (const chunk of stream as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};
const exportZip = async (selections: unknown[]) => {
  const result = await queryAsAdminWithSuccess({ query: EXPORT_MUTATION, variables: { selections } });
  const exportId = result.data?.configPresetExport.id as string;
  const zip = await readStream(await downloadFile(exportId));
  await deleteFile(testContext, ADMIN_USER, exportId, { forceDelete: true });
  return zip;
};
const uploadZip = async (content: Buffer) => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const importData = async (fileId: string, selections: unknown[], dryRun = false) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { type: string; key: string; status: string; reason: string | null }[];
};
const zipTexts = async (zip: Buffer): Promise<{ path: string; text: string }[]> => {
  const directory = await unzipper.Open.buffer(zip);
  const files = directory.files.filter(({ type }: { type: string }) => type === 'File');
  return Promise.all(files.map(async (file: { path: string; buffer: () => Promise<Buffer> }) => ({ path: file.path, text: (await file.buffer()).toString('utf8') })));
};

const field = (name: string, type: string, extra: Record<string, unknown> = {}) => ({
  id: name,
  name,
  label: name,
  type,
  required: false,
  attributeMapping: { entity: 'main_entity', attributeName: name },
  ...extra,
});
// A form that names real references (a marking, a label, a group) and a user: the bundle carries the first, never the second
const formSchema = () => ({
  version: '2.0',
  mainEntityType: 'Report',
  isDraftByDefault: true,
  draftDefaults: {
    objectAssignee: { isEditable: true, isRequired: false, defaults: [{ value: ADMIN_USER.id, label: 'admin' }] },
    authorizedMembers: {
      enabled: true,
      isRequired: false,
      defaults: [
        { value: group.internal_id, label: GROUP_NAME, type: 'Group', accessRight: 'edit', groupsRestriction: [] },
        { value: ADMIN_USER.id, label: 'admin', type: 'User', accessRight: 'admin', groupsRestriction: [] },
      ],
    },
  },
  fields: [
    field('name', 'text', { required: true }),
    field('objectMarking', 'objectMarking', { defaultValue: [marking.internal_id] }),
    field('objectLabel', 'objectLabel', { defaultValue: [{ value: label.internal_id, label: label.value }] }),
  ],
});
const addTestForm = (name: string, active = false) => {
  return addForm(testContext, ADMIN_USER, { name, description: 'Round trip', form_schema: JSON.stringify(formSchema()), active });
};
const testForms = async () => {
  const forms = await findAllForms(testContext, ADMIN_USER) as BasicStoreEntityForm[];
  return forms.filter(({ name }) => name.startsWith(PREFIX)).sort((a, b) => a.name.localeCompare(b.name));
};
const schemaOf = (form: BasicStoreEntityForm) => JSON.parse(form.form_schema) as FormSchemaDefinition;
const deleteTestForms = async () => {
  const forms = await testForms();
  for (let i = 0; i < forms.length; i += 1) {
    await formDelete(testContext, ADMIN_USER, forms[i].id);
  }
};

describe('Config preset import: form intakes', () => {
  beforeAll(async () => {
    marking = await findMarkingById(testContext, ADMIN_USER, TLP_AMBER) as Entity;
    group = await findGroupById(testContext, ADMIN_USER, groupStandardId(GROUP_NAME)) as Entity;
    label = ((await findAllLabels(testContext, ADMIN_USER, {})) as Entity[])[0];
    expect(marking, 'the TLP:AMBER marking of the platform').toBeTruthy();
    expect(group, 'the Default group of the platform').toBeTruthy();
    expect(label, 'a label of the test data').toBeTruthy();
  });
  afterEach(async () => {
    await deleteTestForms();
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    await queryAsAdmin({ query: gql`mutation ConfigPresetFormIntakesClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });
  afterAll(deleteTestForms);

  it('exports a form without its users nor any internal id, and imports it back as an inactive form with the references of the platform', async () => {
    const form = await addTestForm(FORM_NAME, true);
    const zip = await exportZip([{ type: 'formIntakes', items: [form.standard_id] }]);
    const files = (await zipTexts(zip)).filter(({ path }) => path.includes('form_intakes/'));
    expect(files).toHaveLength(1);
    // The marking, the label and the group travel by standard id: no internal id, no user
    [marking.internal_id, label.internal_id, group.internal_id, ADMIN_USER.id].forEach((id) => expect(files[0].text).not.toContain(id));
    [marking.standard_id, group.standard_id].forEach((id) => expect(files[0].text).toContain(id));
    const exported = JSON.parse(files[0].text).configuration;
    expect(exported.active).toBe(true);
    expect(exported.form_schema.draftDefaults.objectAssignee.defaults).toEqual([]);

    await formDelete(testContext, ADMIN_USER, form.id);
    const results = await importData(await uploadZip(zip), [{ type: 'formIntakes' }]);
    expect(results).toMatchObject([{ type: 'formIntakes', key: form.standard_id, status: 'CREATED' }]);
    const [created] = await testForms();
    expect(created).toMatchObject({ name: FORM_NAME, description: 'Round trip', main_entity_type: 'Report', active: false });
    const schema = schemaOf(created);
    expect(schema.fields.find(({ name }) => name === 'objectMarking')?.defaultValue).toEqual([marking.internal_id]);
    expect(schema.fields.find(({ name }) => name === 'objectLabel')?.defaultValue).toEqual([{ value: label.internal_id, label: label.value }]);
    // The group is back as a group of the platform, the user is not named any more
    expect(schema.draftDefaults?.authorizedMembers?.defaults).toEqual([{ value: group.internal_id, label: GROUP_NAME, type: 'Group', accessRight: 'edit', groupsRestriction: [] }]);
    expect(schema.draftDefaults?.objectAssignee?.defaults).toEqual([]);
  });

  it('keeps the users of a form that its own export overwrites: nothing changes and it stays active', async () => {
    const form = await addTestForm(FORM_NAME, true);
    const zip = await exportZip([{ type: 'formIntakes', items: [form.standard_id] }]);
    const fileId = await uploadZip(zip);
    const expected = [{ type: 'formIntakes', key: form.standard_id, status: 'SKIPPED', reason: 'Already up to date' }];
    expect(await importData(fileId, [{ type: 'formIntakes' }], true)).toEqual(expected);
    expect(await importData(fileId, [{ type: 'formIntakes' }])).toEqual(expected);
    const [unchanged] = await testForms();
    expect(unchanged).toMatchObject({ id: form.id, active: true });
    expect(schemaOf(unchanged)).toEqual(formSchema());
  });

  it('overwrites a changed form with the bundle, keeps its users, and sets it inactive', async () => {
    const form = await addTestForm(FORM_NAME, true);
    const zip = await exportZip([{ type: 'formIntakes', items: [form.standard_id] }]);
    const fileId = await uploadZip(zip);
    // The form changes after the export: the bundle is the older version
    const changed = { ...formSchema(), fields: [...formSchema().fields, field('description', 'textarea')] };
    await formEditField(testContext, ADMIN_USER, form.id, [{ key: 'form_schema', value: [JSON.stringify(changed)] }]);

    const dry = await importData(fileId, [{ type: 'formIntakes' }], true);
    expect(dry).toMatchObject([{ status: 'OVERWRITTEN' }]);
    expect((await testForms())[0].active).toBe(true);
    expect(await importData(fileId, [{ type: 'formIntakes' }])).toEqual(dry);
    const [overwritten] = await testForms();
    expect(overwritten).toMatchObject({ id: form.id, active: false });
    // The schema is the one of the bundle, the assignee and the user member are still the ones of the form
    expect(schemaOf(overwritten)).toEqual(formSchema());
  });

  it('adds a copy under the next free name and leaves the form alone', async () => {
    const form = await addTestForm(FORM_NAME, true);
    const zip = await exportZip([{ type: 'formIntakes', items: [form.standard_id] }]);
    const results = await importData(await uploadZip(zip), [{ type: 'formIntakes', item_modes: [{ key: form.standard_id, mode: 'COPY' }] }]);
    expect(results).toMatchObject([{ key: form.standard_id, status: 'CREATED', reason: `Added as "${FORM_NAME} (1)"` }]);
    const forms = await testForms();
    expect(forms.map(({ name, active }) => [name, active])).toEqual([[FORM_NAME, true], [`${FORM_NAME} (1)`, false]]);
    // The copy is a form of the bundle: no user
    const copy = forms.find(({ name }) => name === `${FORM_NAME} (1)`) as BasicStoreEntityForm;
    expect(schemaOf(copy).draftDefaults?.objectAssignee?.defaults).toEqual([]);
    expect(schemaOf(forms[0])).toEqual(formSchema());
  });
});
