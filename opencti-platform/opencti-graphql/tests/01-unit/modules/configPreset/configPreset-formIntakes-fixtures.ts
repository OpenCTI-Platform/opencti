import type { BasicStoreEntityForm } from '../../../../src/modules/form/form-types';

// What the schemas of the forms refer to. The internal ids are uuids, as the platform makes them: the remap of the ids only converts those.
export const analystsFormGroup = {
  id: '6c1f0d2e-8a4b-4f3c-9d5e-1a2b3c4d5e6f',
  internal_id: '6c1f0d2e-8a4b-4f3c-9d5e-1a2b3c4d5e6f',
  standard_id: 'group--0a1b2c3d-4e5f-5a6b-8c7d-9e0f1a2b3c4d',
  entity_type: 'Group',
};
export const reviewersFormGroup = {
  id: '7d2e1f3a-9b5c-4a4d-8e6f-2b3c4d5e6f70',
  internal_id: '7d2e1f3a-9b5c-4a4d-8e6f-2b3c4d5e6f70',
  standard_id: 'group--1b2c3d4e-5f6a-5b7c-9d8e-0f1a2b3c4d5e',
  entity_type: 'Group',
};
export const amberFormMarking = {
  id: '8e3f2a4b-0c6d-4b5e-9f70-3c4d5e6f7081',
  internal_id: '8e3f2a4b-0c6d-4b5e-9f70-3c4d5e6f7081',
  standard_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
  entity_type: 'Marking-Definition',
};
export const phishingFormLabel = {
  id: 'd38e7f90-5b12-4a03-8ec5-819203142536',
  internal_id: 'd38e7f90-5b12-4a03-8ec5-819203142536',
  standard_id: 'label--4e5f6a7b-8c9d-5e0f-a1b2-3c4d5e6f7081',
  entity_type: 'Label',
};
export const formUser = {
  id: '9f4a3b5c-1d7e-4c6f-8a81-4d5e6f708192',
  internal_id: '9f4a3b5c-1d7e-4c6f-8a81-4d5e6f708192',
  standard_id: 'user--2c3d4e5f-6a7b-5c8d-8e9f-1a2b3c4d5e6f',
  entity_type: 'User',
};
export const formOrganization = {
  id: 'a05b4c6d-2e8f-4d70-9b92-5e6f70819203',
  internal_id: 'a05b4c6d-2e8f-4d70-9b92-5e6f70819203',
  standard_id: 'identity--3d4e5f6a-7b8c-5d9e-9fa0-2b3c4d5e6f70',
  entity_type: 'Organization',
};
// A group and a marking that exist nowhere
export const deletedGroupId = 'b16c5d7e-3f90-4e81-8ca3-6f7081920314';
export const deletedMarkingId = 'c27d6e8f-4a01-4f92-9db4-708192031425';

export const FORM_REFERENCED_ENTITIES = [analystsFormGroup, reviewersFormGroup, amberFormMarking, phishingFormLabel, formUser, formOrganization];

const field = (name: string, type: string, extra: Record<string, unknown> = {}) => ({
  id: name,
  name,
  label: name,
  type,
  required: false,
  attributeMapping: { entity: 'main_entity', attributeName: name },
  ...extra,
});

// Every reference of a schema: the users and the organizations are not exported, the groups and the markings are, as standard ids
export const incidentFormSchema = {
  version: '2.0',
  mainEntityType: 'Incident',
  isDraftByDefault: true,
  draftDefaults: {
    objectAssignee: { isEditable: true, isRequired: false, defaults: [{ value: formUser.id, label: 'A user' }] },
    objectParticipant: { isEditable: true, isRequired: false, defaults: [{ value: formUser.id, label: 'A user' }] },
    author: { type: 'static', isEditable: true, isRequired: false, defaultValue: formOrganization.id, defaultValueLabel: 'An organization', defaultValueType: 'Organization' },
    authorizedMembers: {
      enabled: true,
      isRequired: false,
      defaults: [
        { value: 'CREATORS', label: 'Creators', type: 'Dynamic from draft', accessRight: 'admin', groupsRestriction: [] },
        { value: analystsFormGroup.id, label: 'Analysts', type: 'Group', accessRight: 'edit', groupsRestriction: [] },
        { value: formUser.id, label: 'A user', type: 'User', accessRight: 'view', groupsRestriction: [] },
        { value: formOrganization.id, label: 'An organization', type: 'Organization', accessRight: 'view', groupsRestriction: [] },
        { value: 'AUTHOR', label: 'Draft author', type: 'Dynamic from draft', accessRight: 'view', groupsRestriction: [{ value: reviewersFormGroup.id, label: 'Reviewers' }] },
        { value: reviewersFormGroup.id, label: 'Reviewers', type: 'Group', accessRight: 'view', groupsRestriction: [{ value: deletedGroupId, label: 'Deleted group' }] },
        { type: 'CREATOR' },
        { type: 'AUTHOR_ORG', intersectionGroup: analystsFormGroup.id },
        { type: 'AUTHOR_ORG', intersectionGroup: deletedGroupId },
      ],
    },
  },
  fields: [
    field('name', 'text', { required: true }),
    field('createdBy', 'createdBy', { defaultValue: formOrganization.id }),
    field('objectMarking', 'objectMarking', { defaultValue: [amberFormMarking.id, { value: reviewersFormGroup.id }, deletedMarkingId] }),
    field('objectLabel', 'objectLabel', { defaultValue: [{ value: phishingFormLabel.id, label: 'phishing' }, 'intake'] }),
  ],
};

export const reportFormSchema = {
  version: '2.0',
  mainEntityType: 'Report',
  fields: [field('name', 'text', { required: true }), field('objectMarking', 'objectMarking', { defaultValue: [{ value: amberFormMarking.id, label: 'TLP:AMBER' }] })],
};

const toForm = (id: string, name: string, schema: object, active: boolean, description?: string) => ({
  id: `${id}-id`,
  internal_id: `${id}-id`,
  standard_id: `form--${id}`,
  entity_type: 'Form',
  name,
  description,
  main_entity_type: (schema as { mainEntityType: string }).mainEntityType,
  form_schema: JSON.stringify(schema),
  active,
  // Never exported
  creator_id: ['someone-id'],
  created_at: '2026-01-01T00:00:00.000Z',
} as unknown as BasicStoreEntityForm);

export const incidentForm = toForm('4e5f6a7b-8c9d-5e0f-a1b2-3c4d5e6f7081', 'Incident intake', incidentFormSchema, true, 'Reports an incident');
export const reportForm = toForm('5f6a7b8c-9d0e-5f1a-b2c3-4d5e6f708192', 'Report intake', reportFormSchema, false);

export const ALL_FORM_INTAKES = [incidentForm, reportForm];
