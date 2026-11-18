import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/modules/form/form-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/form/form-domain')>()),
  addForm: vi.fn(),
  findAllForms: vi.fn(),
  formEditField: vi.fn(),
}));

import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { addForm, findAllForms, formEditField } from '../../../../src/modules/form/form-domain';
import { exportFormIntake } from '../../../../src/modules/form/form-export';
import { importFormIntake } from '../../../../src/modules/form/form-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { FormSchemaDefinition } from '../../../../src/modules/form/form-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import {
  amberFormMarking,
  analystsFormGroup,
  FORM_REFERENCED_ENTITIES,
  formOrganization,
  formUser,
  incidentForm,
  phishingFormLabel,
  reportForm,
  reviewersFormGroup,
} from '../configPreset/configPreset-formIntakes-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id', capabilities: [{ name: 'BYPASS' }] } as AuthUser;

// The platform that imports: the same groups and marking, under other internal ids
const targetGroup = { ...analystsFormGroup, id: 'e2a3b4c5-6d7e-4f80-91a2-b3c4d5e6f708', internal_id: 'e2a3b4c5-6d7e-4f80-91a2-b3c4d5e6f708' };
const targetReviewers = { ...reviewersFormGroup, id: 'f3b4c5d6-7e8f-4091-a2b3-c4d5e6f70819', internal_id: 'f3b4c5d6-7e8f-4091-a2b3-c4d5e6f70819' };
const targetMarking = { ...amberFormMarking, id: '04c5d6e7-8f90-41a2-b3c4-d5e6f708192a', internal_id: '04c5d6e7-8f90-41a2-b3c4-d5e6f708192a' };
const targetLabel = { ...phishingFormLabel, id: '15d6e7f8-9a01-42b3-84c5-e6f708192a3b', internal_id: '15d6e7f8-9a01-42b3-84c5-e6f708192a3b' };
const TARGET_ENTITIES = [targetGroup, targetReviewers, targetMarking, targetLabel];

const lookup = (entities: { id: string; standard_id: string }[]) => async (_ctx: unknown, _user: unknown, ids: string[]) => {
  const found = entities.flatMap((entity) => [[entity.id, entity], [entity.standard_id, entity]] as const).filter(([id]) => ids.includes(id));
  return Object.fromEntries(found) as never;
};

// What the bundle carries of a form: the export of the source platform
const exportedConfiguration = async (form = incidentForm) => {
  vi.mocked(internalFindByIds).mockImplementation(lookup(FORM_REFERENCED_ENTITIES));
  const configuration = await exportFormIntake(context, user, form);
  vi.mocked(internalFindByIds).mockImplementation(lookup(TARGET_ENTITIES));
  return configuration;
};

const existingForm = (overrides: object = {}) => ({ ...incidentForm, id: 'existing-form-id', internal_id: 'existing-form-id', ...overrides }) as typeof incidentForm;

describe('Form intake import', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(findAllForms).mockResolvedValue([]);
    vi.mocked(addForm).mockResolvedValue({} as never);
    vi.mocked(formEditField).mockResolvedValue({} as never);
    vi.mocked(internalFindByIds).mockImplementation(lookup(TARGET_ENTITIES));
  });

  describe('creation', () => {
    it('creates the form inactive, whatever its state in the bundle, with the groups and the marking of the platform', async () => {
      const configuration = await exportedConfiguration();
      expect(configuration.active).toBe(true);
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'created', exists: false });
      expect(result.reason).toBeUndefined();
      expect(addForm).toHaveBeenCalledTimes(1);
      const input = vi.mocked(addForm).mock.calls[0][2];
      expect(input).toMatchObject({ name: 'Incident intake', description: 'Reports an incident', active: false });
      const schema = JSON.parse(input.form_schema) as FormSchemaDefinition;
      // The ids of the platform, not the ones of the bundle
      expect(schema.fields.find(({ name }) => name === 'objectMarking')?.defaultValue).toEqual([targetMarking.internal_id]);
      // The label that exists on the platform is found by its standard id, a label given by its value is kept
      expect(schema.fields.find(({ name }) => name === 'objectLabel')?.defaultValue).toEqual([{ value: targetLabel.internal_id, label: 'phishing' }, 'intake']);
      const members = schema.draftDefaults?.authorizedMembers?.defaults;
      expect(members).toContainEqual({ value: targetGroup.internal_id, label: 'Analysts', type: 'Group', accessRight: 'edit', groupsRestriction: [] });
      expect(members).toContainEqual({ type: 'AUTHOR_ORG', intersectionGroup: targetGroup.internal_id });
      const serialized = JSON.stringify(schema);
      [analystsFormGroup.id, amberFormMarking.id, analystsFormGroup.standard_id, amberFormMarking.standard_id].forEach((id) => expect(serialized).not.toContain(id));
    });

    it('writes nothing in a dry run, and decides the same result', async () => {
      const configuration = await exportedConfiguration();
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
      expect(result).toMatchObject({ status: 'created', exists: false });
      expect(addForm).not.toHaveBeenCalled();
      expect(formEditField).not.toHaveBeenCalled();
    });

    it('leaves out the groups and the markings the platform does not know, and says so', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(internalFindByIds).mockImplementation(lookup([]));
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'created', reason: 'Groups, markings or labels not found are left out of the form' });
      const schema = JSON.parse(vi.mocked(addForm).mock.calls[0][2].form_schema) as FormSchemaDefinition;
      expect(schema.fields.find(({ name }) => name === 'objectMarking')?.defaultValue).toEqual([]);
      // A label given by its value does not depend on the platform
      expect(schema.fields.find(({ name }) => name === 'objectLabel')?.defaultValue).toEqual(['intake']);
      const serialized = JSON.stringify(schema);
      [analystsFormGroup.standard_id, amberFormMarking.standard_id].forEach((id) => expect(serialized).not.toContain(id));
      // What does not depend on the platform stays
      expect(schema.draftDefaults?.authorizedMembers?.defaults).toContainEqual({ type: 'CREATOR' });
    });

    it('never takes a user or an organization of a file that carries some', async () => {
      const configuration = await exportedConfiguration();
      const schema = configuration.form_schema as FormSchemaDefinition;
      schema.draftDefaults!.objectAssignee!.defaults = [{ value: formUser.id, label: 'A user' }];
      schema.draftDefaults!.author = { type: 'static', isEditable: true, isRequired: false, defaultValue: formOrganization.id };
      schema.draftDefaults!.authorizedMembers!.defaults.push({ value: formUser.id, type: 'User', accessRight: 'view', groupsRestriction: [] });
      // The platform knows them: a form never names them
      vi.mocked(internalFindByIds).mockImplementation(lookup([...TARGET_ENTITIES, formUser, formOrganization]));
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'created' });
      const imported = JSON.parse(vi.mocked(addForm).mock.calls[0][2].form_schema) as FormSchemaDefinition;
      expect(imported.draftDefaults?.objectAssignee?.defaults).toEqual([]);
      expect(imported.draftDefaults?.author).toEqual({ type: 'none', isEditable: true, isRequired: false });
      expect(JSON.stringify(imported)).not.toContain(formUser.id);
    });

    it('trims the name, and gives a form without description an empty one', async () => {
      const configuration = { ...(await exportedConfiguration(reportForm)), name: '  Report intake  ' };
      await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(vi.mocked(addForm).mock.calls[0][2]).toMatchObject({ name: 'Report intake', description: '', active: false });
    });
  });

  describe('a form that exists', () => {
    it('overwrites its schema and its description, and sets it inactive', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(findAllForms).mockResolvedValue([existingForm({ description: 'Old', form_schema: JSON.stringify({ version: '2.0', mainEntityType: 'Incident', fields: [] }), active: true })]);
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(addForm).not.toHaveBeenCalled();
      expect(formEditField).toHaveBeenCalledTimes(1);
      const [, , formId, patch] = vi.mocked(formEditField).mock.calls[0];
      expect(formId).toBe('existing-form-id');
      expect(patch).toContainEqual({ key: 'active', value: ['false'] });
      expect(patch.map(({ key }) => key)).toEqual(['description', 'form_schema', 'active']);
    });

    it('does not touch the state of a form that is already inactive', async () => {
      const configuration = await exportedConfiguration();
      const different = JSON.stringify({ version: '2.0', mainEntityType: 'Incident', fields: [] });
      vi.mocked(findAllForms).mockResolvedValue([existingForm({ description: 'Old', form_schema: different, active: false })]);
      await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(vi.mocked(formEditField).mock.calls[0][3].map(({ key }) => key)).toEqual(['description', 'form_schema']);
    });

    it('overwrites in a dry run without writing', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(findAllForms).mockResolvedValue([existingForm({ form_schema: JSON.stringify({ version: '2.0', mainEntityType: 'Incident', fields: [] }) })]);
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
      expect(result.status).toBe('overwritten');
      expect(formEditField).not.toHaveBeenCalled();
    });

    it('skips a form that is already as the bundle has it', async () => {
      const configuration = await exportedConfiguration();
      // Written by an earlier import: the schema of the platform, as a string
      await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      const written = vi.mocked(addForm).mock.calls[0][2];
      vi.mocked(findAllForms).mockResolvedValue([existingForm({ description: written.description, form_schema: written.form_schema, active: true })]);
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
      expect(formEditField).not.toHaveBeenCalled();
    });

    it('does not touch the description of a form when the file has none, and clears it when the bundle exports an empty one', async () => {
      const { description, ...withoutDescription } = await exportedConfiguration(reportForm);
      expect(description).toBe('');
      vi.mocked(findAllForms).mockResolvedValue([existingForm({
        description: 'Old',
        form_schema: JSON.stringify({ version: '2.0', mainEntityType: 'Report', fields: [] }),
      })]);
      await importFormIntake(context, user, withoutDescription, { mode: ConfigImportMode.Overwrite });
      expect(vi.mocked(formEditField).mock.calls[0][3].map(({ key }) => key)).toEqual(['form_schema', 'active']);
      await importFormIntake(context, user, { ...withoutDescription, description }, { mode: ConfigImportMode.Overwrite });
      expect(vi.mocked(formEditField).mock.calls[1][3]).toContainEqual({ key: 'description', value: [''] });
    });

    it('says what was left out of an overwritten form, the same in a dry run as in the real run', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(findAllForms).mockResolvedValue([existingForm({ form_schema: JSON.stringify({ version: '2.0', mainEntityType: 'Incident', fields: [] }), active: true })]);
      vi.mocked(internalFindByIds).mockImplementation(lookup([]));
      const dryRun = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
      expect(formEditField).not.toHaveBeenCalled();
      const real = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(real).toMatchObject({ status: 'overwritten', reason: 'Groups, markings or labels not found are left out of the form' });
      expect(dryRun).toEqual(real);
      expect(formEditField).toHaveBeenCalledTimes(1);
    });

    it('refuses to guess between several forms of the same name and type, and finds them by name and type', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(findAllForms).mockResolvedValue([existingForm(), existingForm({ id: 'other-id' })]);
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'failed', code: 'ambiguous', reason: 'Several form intakes have this name', exists: true });
      expect(formEditField).not.toHaveBeenCalled();
      const { filters } = vi.mocked(findAllForms).mock.calls[0][2] as { filters: { filters: { key: string[]; values: string[] }[] } };
      expect(filters.filters).toEqual([{ key: ['name'], values: ['Incident intake'] }, { key: ['main_entity_type'], values: ['Incident'] }]);
    });
  });

  describe('copy', () => {
    it('creates the form under its own name when nothing has it', async () => {
      const configuration = await exportedConfiguration();
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Copy });
      expect(result).toMatchObject({ status: 'created', exists: false });
      expect(result.reason).toBeUndefined();
      expect(vi.mocked(addForm).mock.calls[0][2].name).toBe('Incident intake');
    });

    it('adds a copy under the first free name, and leaves the existing form alone, even when several have the name', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(findAllForms).mockImplementation(async (_ctx, _user, opts) => {
        const name = (opts as { filters: { filters: { values: string[] }[] } }).filters.filters[0].values[0];
        return name === 'Incident intake' || name === 'Incident intake (1)' ? [existingForm(), existingForm({ id: 'other-id' })] : [];
      });
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Copy });
      expect(result).toMatchObject({ status: 'created', exists: true, reason: 'Added as "Incident intake (2)"' });
      expect(vi.mocked(addForm).mock.calls[0][2]).toMatchObject({ name: 'Incident intake (2)', active: false });
      expect(formEditField).not.toHaveBeenCalled();
    });

    it('refuses a copy when no free name is left', async () => {
      const configuration = await exportedConfiguration();
      // Every name is taken
      vi.mocked(findAllForms).mockResolvedValue([existingForm()]);
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Copy });
      expect(result).toMatchObject({ status: 'failed', code: 'name_conflict', reason: 'Form intake already exists', exists: true });
      expect(addForm).not.toHaveBeenCalled();
    });

    it('says what was left out next to the name of the copy', async () => {
      const configuration = await exportedConfiguration();
      vi.mocked(findAllForms).mockImplementation(async (_ctx, _user, opts) => {
        const name = (opts as { filters: { filters: { values: string[] }[] } }).filters.filters[0].values[0];
        return name === 'Incident intake' ? [existingForm()] : [];
      });
      vi.mocked(internalFindByIds).mockImplementation(lookup([]));
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Copy });
      expect(result.reason).toBe('Added as "Incident intake (1)"\nGroups, markings or labels not found are left out of the form');
    });
  });

  describe('the items of one bundle', () => {
    it('refuses a second form with the name and the type of an earlier one: they are one form on the platform', async () => {
      const configuration = await exportedConfiguration();
      const reservedKeys = new Set<string>();
      const first = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      const second = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      expect(first.status).toBe('created');
      expect(second).toMatchObject({ status: 'failed', code: 'duplicate', reason: 'Another form intake of the bundle has this name' });
    });

    it('tells the forms of the same name apart by their main entity type, and the names by their case', async () => {
      const reservedKeys = new Set<string>();
      const incident = await exportedConfiguration();
      const report = { ...(await exportedConfiguration(reportForm)), name: 'INCIDENT INTAKE' };
      const sameNameOtherType = await importFormIntake(context, user, report, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      const sameNameAndType = await importFormIntake(context, user, { ...incident, name: 'incident intake' }, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      const incidentAgain = await importFormIntake(context, user, incident, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      expect(sameNameOtherType.status).toBe('created');
      expect(sameNameAndType.status).toBe('created');
      expect(incidentAgain).toMatchObject({ status: 'failed', code: 'duplicate' });
    });

    it('tells the names apart as the platform does: the accents do not make another form', async () => {
      const configuration = await exportedConfiguration();
      const reservedKeys = new Set<string>();
      const first = await importFormIntake(context, user, { ...configuration, name: 'Café intake' }, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      const second = await importFormIntake(context, user, { ...configuration, name: 'Cafe intake' }, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      expect(first.status).toBe('created');
      expect(second).toMatchObject({ status: 'failed', code: 'duplicate' });
      // The letters that do not decompose are folded as well
      const third = await importFormIntake(context, user, { ...configuration, name: 'Straße intake' }, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      const fourth = await importFormIntake(context, user, { ...configuration, name: 'Strasse intake' }, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedKeys });
      expect(third.status).toBe('created');
      expect(fourth).toMatchObject({ status: 'failed', code: 'duplicate' });
    });

    it('copies the forms of the same name one after the other under free names', async () => {
      const configuration = await exportedConfiguration();
      const reservedKeys = new Set<string>();
      const first = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Copy, dryRun: true, reservedKeys });
      const second = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Copy, dryRun: true, reservedKeys });
      expect(first.reason).toBeUndefined();
      expect(second.reason).toBe('Added as "Incident intake (1)"');
    });
  });

  describe('validation', () => {
    const refused = async (configuration: unknown) => {
      const result = await importFormIntake(context, user, configuration, { mode: ConfigImportMode.Overwrite });
      expect(addForm).not.toHaveBeenCalled();
      expect(formEditField).not.toHaveBeenCalled();
      return result;
    };

    it('refuses a configuration with an unknown key, a short name, or a schema that is not an object', async () => {
      const configuration = await exportedConfiguration();
      expect(await refused({ ...configuration, extra: true })).toMatchObject({ status: 'failed', code: 'invalid' });
      expect(await refused({ ...configuration, name: ' a ' })).toMatchObject({ status: 'failed', code: 'invalid' });
      expect(await refused({ ...configuration, form_schema: JSON.stringify(configuration.form_schema) })).toMatchObject({ status: 'failed', code: 'invalid' });
      expect(await refused(null)).toMatchObject({ status: 'failed', code: 'invalid' });
    });

    it('refuses a relationship whose fields are not objects, instead of failing while the references are rewritten', async () => {
      const configuration = await exportedConfiguration();
      const relationship = { id: 'r', fromEntity: 'main_entity', toEntity: 'x', relationshipType: 'uses', fields: [null] };
      const result = await refused({ ...configuration, form_schema: { ...(configuration.form_schema as object), relationships: [relationship] } });
      expect(result).toMatchObject({ status: 'failed', code: 'invalid' });
    });

    it('refuses a schema that is not a valid form schema, and says where', async () => {
      const configuration = await exportedConfiguration();
      const result = await refused({ ...configuration, form_schema: { version: '2.0', mainEntityType: 'Incident' } });
      expect(result).toMatchObject({ status: 'failed', code: 'invalid' });
      expect(result.reason).toContain('form_schema:');
      expect(result.reason).toContain('fields');
      expect(result.reason).not.toContain('\n');
    });

    it('imports a form for an entity type the platform does not have: it works once the type exists', async () => {
      const configuration = await exportedConfiguration();
      const schema = { ...(configuration.form_schema as object), mainEntityType: 'Spaceship' };
      const result = await importFormIntake(context, user, { ...configuration, form_schema: schema }, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'created', exists: false });
      expect(vi.mocked(addForm).mock.calls[0][2]).toMatchObject({ active: false });
      expect(JSON.parse(vi.mocked(addForm).mock.calls[0][2].form_schema).mainEntityType).toBe('Spaceship');
    });
  });
});
