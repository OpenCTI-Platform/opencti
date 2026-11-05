import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_task.py
const TASK_ADD = `
  mutation TaskAdd($input: TaskAddInput!) {
    taskAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_task.py:create (no stix_id, stix ids, external references, revoked, confidence,
// lang nor modified in its input, even when given)
const createTask = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_task] Missing parameters: name');
    return null;
  }
  return mutate(context, TASK_ADD, 'taskAdd', {
    created: kw(kwargs, 'created'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    due_date: kw(kwargs, 'due_date'),
    objects: kw(kwargs, 'objects'),
    createdBy: kw(kwargs, 'createdBy'),
    objectLabel: kw(kwargs, 'objectLabel'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    objectAssignee: kw(kwargs, 'objectAssignee'),
    objectParticipant: kw(kwargs, 'objectParticipant'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    upsertOperations: kw(kwargs, 'upsert_operations'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
  });
};

// pycti opencti_task.py:import_from_stix2
export const importTask = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [
    ['x_opencti_stix_ids', 'stix_ids'],
    ['x_opencti_granted_refs', 'granted_refs'],
    ['x_opencti_workflow_id', 'workflow_id'],
    ['x_opencti_assignee_ids', 'assignee_ids'],
    ['x_opencti_participant_ids', 'participant_ids'],
    ['x_opencti_modified_at', 'modified_at'],
    ['opencti_upsert_operations', 'opencti_upsert_operations'],
  ]);
  return createTask(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: field(extras, 'object_ids', []),
    created: field(object, 'created'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    due_date: field(object, 'due_date'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    objectAssignee: field(object, 'x_opencti_assignee_ids'),
    objectParticipant: field(object, 'x_opencti_participant_ids'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
