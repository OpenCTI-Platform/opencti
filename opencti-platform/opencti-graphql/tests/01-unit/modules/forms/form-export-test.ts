import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));

import Ajv from 'ajv';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { exportFormIntake, rewriteFormSchemaReferences } from '../../../../src/modules/form/form-export';
import { FormSchemaDefinitionSchema, type FormSchemaDefinition } from '../../../../src/modules/form/form-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import {
  amberFormMarking,
  analystsFormGroup,
  deletedGroupId,
  deletedMarkingId,
  FORM_REFERENCED_ENTITIES,
  formOrganization,
  formUser,
  phishingFormLabel,
  incidentForm,
  incidentFormSchema,
  reportForm,
  reviewersFormGroup,
} from '../configPreset/configPreset-formIntakes-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id', capabilities: [{ name: 'BYPASS' }] } as AuthUser;

const exportedSchema = async (form = incidentForm) => (await exportFormIntake(context, user, form)).form_schema;

describe('Form intake export', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(internalFindByIds).mockImplementation(async (_ctx, _user, ids) => {
      const found = FORM_REFERENCED_ENTITIES.flatMap((entity) => [[entity.id, entity], [entity.standard_id, entity]] as const).filter(([id]) => ids.includes(id));
      return Object.fromEntries(found) as never;
    });
  });

  it('exports the name, the description, the state and the schema as an object, and nothing else of the entity', async () => {
    const incident = await exportFormIntake(context, user, incidentForm);
    expect(Object.keys(incident)).toEqual(['name', 'description', 'form_schema', 'active']);
    expect(incident).toMatchObject({ name: 'Incident intake', description: 'Reports an incident', active: true });
    // A form without description has an empty one in the file: an overwrite clears the description of the form it finds
    const report = await exportFormIntake(context, user, reportForm);
    expect(report).toMatchObject({ name: 'Report intake', description: '', active: false });
  });

  it('looks up everything the schema refers to once', async () => {
    await exportFormIntake(context, user, incidentForm);
    expect(internalFindByIds).toHaveBeenCalledTimes(1);
    const ids = vi.mocked(internalFindByIds).mock.calls[0][2];
    expect(new Set(ids).size).toBe(ids.length);
    const referenced = [formUser.id, formOrganization.id, analystsFormGroup.id, reviewersFormGroup.id, amberFormMarking.id, deletedGroupId, deletedMarkingId];
    expect(ids).toEqual(expect.arrayContaining(referenced));
  });

  it('makes no lookup for a schema without references', async () => {
    const schema = { version: '2.0', mainEntityType: 'Report', fields: [] };
    await exportFormIntake(context, user, { ...reportForm, form_schema: JSON.stringify(schema) });
    expect(internalFindByIds).not.toHaveBeenCalled();
  });

  it('never exports a user or an organization: the defaults that named them are left empty', async () => {
    const schema = await exportedSchema();
    const { draftDefaults } = schema;
    expect(draftDefaults?.objectAssignee?.defaults).toEqual([]);
    expect(draftDefaults?.objectParticipant?.defaults).toEqual([]);
    // A static author is an identity: the form asks for it like a form that has none, and keeps its rules
    expect(draftDefaults?.author).toEqual({ type: 'none', isEditable: true, isRequired: false });
    expect(schema.fields.find(({ name }) => name === 'createdBy')).not.toHaveProperty('defaultValue');
    const serialized = JSON.stringify(schema);
    [formUser.id, formUser.standard_id, formOrganization.id, formOrganization.standard_id].forEach((id) => expect(serialized).not.toContain(id));
  });

  it('writes the groups and the markings as standard ids, and keeps what an option holds next to its id', async () => {
    const schema = await exportedSchema();
    const markings = schema.fields.find(({ name }) => name === 'objectMarking')?.defaultValue;
    // A group in a marking default and a marking that does not exist are left out
    expect(markings).toEqual([amberFormMarking.standard_id]);
    const report = await exportedSchema(reportForm);
    expect(report.fields.find(({ name }) => name === 'objectMarking')?.defaultValue).toEqual([{ value: amberFormMarking.standard_id, label: 'TLP:AMBER' }]);
    const members = schema.draftDefaults?.authorizedMembers?.defaults;
    expect(members).toContainEqual({ value: analystsFormGroup.standard_id, label: 'Analysts', type: 'Group', accessRight: 'edit', groupsRestriction: [] });
  });

  it('keeps the dynamic members and the legacy rules, and leaves out the members that are not groups', async () => {
    const members = (await exportedSchema()).draftDefaults?.authorizedMembers?.defaults;
    expect(members).toEqual([
      { value: 'CREATORS', label: 'Creators', type: 'Dynamic from draft', accessRight: 'admin', groupsRestriction: [] },
      { value: analystsFormGroup.standard_id, label: 'Analysts', type: 'Group', accessRight: 'edit', groupsRestriction: [] },
      // The author of the draft, restricted to a group that is exported
      {
        value: 'AUTHOR',
        label: 'Draft author',
        type: 'Dynamic from draft',
        accessRight: 'view',
        groupsRestriction: [{ value: reviewersFormGroup.standard_id, label: 'Reviewers' }],
      },
      { type: 'CREATOR' },
      { type: 'AUTHOR_ORG', intersectionGroup: analystsFormGroup.standard_id },
    ]);
  });

  it('leaves out a rule restricted to a group that is not exported: without its restriction it would give access to more members', async () => {
    const schema = await exportedSchema();
    expect(JSON.stringify(schema)).not.toContain(deletedGroupId);
    // The rule of the reviewers group was restricted to the deleted group
    const members = schema.draftDefaults?.authorizedMembers?.defaults ?? [];
    expect(members.filter((member: { value?: string }) => member.value === reviewersFormGroup.standard_id)).toEqual([]);
    expect(members).not.toContainEqual({ type: 'AUTHOR_ORG', intersectionGroup: deletedGroupId });
  });

  it('writes a label under its standard id, keeps a label given by its value, and the rest of the schema as it is', async () => {
    const schema = await exportedSchema();
    expect(schema.fields.find(({ name }) => name === 'objectLabel')?.defaultValue).toEqual([{ value: phishingFormLabel.standard_id, label: 'phishing' }, 'intake']);
    expect(JSON.stringify(schema)).not.toContain(phishingFormLabel.id);
    expect(schema).toMatchObject({ version: '2.0', mainEntityType: 'Incident', isDraftByDefault: true });
    expect(schema.fields.map(({ name }) => name)).toEqual(incidentFormSchema.fields.map(({ name }) => name));
  });

  it('rewrites the references of the fields of a relationship and of the top level defaults', () => {
    const schema = {
      version: '2.0',
      mainEntityType: 'Malware',
      markings: [amberFormMarking.id, deletedMarkingId],
      createdByRef: formOrganization.id,
      fields: [],
      relationships: [{
        id: 'uses',
        fromEntity: 'main_entity',
        toEntity: 'x',
        relationshipType: 'uses',
        fields: [{ id: 'm', name: 'm', label: 'm', type: 'objectMarking', required: false, attributeMapping: { entity: 'main_entity', attributeName: 'm' }, defaultValue: [amberFormMarking.id] }],
      }],
    } as unknown as FormSchemaDefinition;
    const rewritten = rewriteFormSchemaReferences(schema, (_kind, id) => (id === amberFormMarking.id ? 'marking-standard-id' : null));
    expect(rewritten.markings).toEqual(['marking-standard-id']);
    expect(rewritten).not.toHaveProperty('createdByRef');
    expect(rewritten.relationships?.[0].fields?.[0].defaultValue).toEqual(['marking-standard-id']);
  });

  it('drops what a field maps to a user or an identity, whatever its type, and keeps the rules that carry no id', () => {
    const onlyGroups = (kind: string, id: string) => (kind === 'group' || kind === 'member' ? `standard-${id}` : null);
    const schema = {
      version: '2.0',
      mainEntityType: 'Incident',
      fields: [
        { id: 'a', name: 'a', label: 'a', type: 'text', required: false, attributeMapping: { entity: 'main_entity', attributeName: 'objectAssignee' }, defaultValue: formUser.id },
        { id: 'p', name: 'p', label: 'p', type: 'text', required: false, attributeMapping: { entity: 'main_entity', attributeName: 'objectParticipant' }, defaultValue: formUser.id },
        { id: 'c', name: 'c', label: 'c', type: 'text', required: false, attributeMapping: { entity: 'main_entity', attributeName: 'createdBy' }, defaultValue: formOrganization.id },
        { id: 'm', name: 'm', label: 'm', type: 'text', required: false, attributeMapping: { entity: 'main_entity', attributeName: 'objectMarking' }, defaultValue: [amberFormMarking.id] },
      ],
      draftDefaults: {
        authorizedMembers: {
          enabled: true,
          isEditable: true,
          defaults: ['CREATORS', 'AUTHOR', { type: 'AUTHOR_ORG' }, analystsFormGroup.id, { value: 'some-group', groupsRestriction: ['other-group'] }],
        },
      },
    } as unknown as FormSchemaDefinition;
    const rewritten = rewriteFormSchemaReferences(schema, onlyGroups);
    ['a', 'p', 'c'].forEach((id) => expect(rewritten.fields.find((field) => field.id === id)).not.toHaveProperty('defaultValue'));
    // A marking mapped by its attribute only is a marking: the resolver leaves it out, the default is an empty list
    expect(rewritten.fields.find((field) => field.id === 'm')?.defaultValue).toEqual([]);
    expect(rewritten.draftDefaults?.authorizedMembers?.defaults).toEqual([
      'CREATORS',
      'AUTHOR',
      { type: 'AUTHOR_ORG' },
      `standard-${analystsFormGroup.id}`,
      { value: 'standard-some-group', groupsRestriction: ['standard-other-group'] },
    ]);
    // A user as a bare id is not exported
    const users = rewriteFormSchemaReferences(schema, (kind) => (kind === 'group' ? 'g' : null));
    expect(users.draftDefaults?.authorizedMembers?.defaults).toEqual(['CREATORS', 'AUTHOR', { type: 'AUTHOR_ORG' }]);
  });

  it('does not fail on a stored form whose relationship has a field that is not an object', () => {
    const schema = {
      version: '2.0',
      mainEntityType: 'Malware',
      fields: [],
      relationships: [{ id: 'uses', fromEntity: 'main_entity', toEntity: 'x', relationshipType: 'uses', fields: [null] }],
    } as unknown as FormSchemaDefinition;
    expect(() => rewriteFormSchemaReferences(schema, () => null)).not.toThrow();
  });

  it('does not change the schema it is given', () => {
    const schema = structuredClone(incidentFormSchema) as unknown as FormSchemaDefinition;
    rewriteFormSchemaReferences(schema, () => null);
    expect(schema).toEqual(incidentFormSchema);
  });

  it('exports a schema that is still a valid form schema', async () => {
    const validate = new Ajv().compile(FormSchemaDefinitionSchema);
    const valid = validate(await exportedSchema());
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it('refuses a schema that is not JSON', async () => {
    await expect(exportFormIntake(context, user, { ...reportForm, form_schema: '{ not json' })).rejects.toThrow('The schema of a form intake is not a valid JSON');
  });
});
