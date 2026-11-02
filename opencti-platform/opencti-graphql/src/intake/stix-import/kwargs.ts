import type { ImportContext } from './context';
import type { StixObject } from './types';
import { contains, getAttributeInExtension, required, setItem } from './utils';

// Building blocks of the ports of pycti's methods: `create` functions take the keyword arguments
// pycti's create methods take (kw), `importX` functions mirror import_from_stix2 (field, extras).

export type Kwargs = Record<string, any>;

// pycti kwargs.get(key, default): a key given as undefined (never provided) stays undefined (own
// keys only: the kwargs are built by the port)
export const kw = (kwargs: Kwargs, key: string, defaultValue: unknown = null) => (Object.prototype.hasOwnProperty.call(kwargs, key) ? kwargs[key] : defaultValue);

// pycti `stix_object[key] if key in stix_object else None` (and `x[key] if key in x else default`),
// with Python's `in` and `[]` on whatever the value is (own keys only, a str or a list fails as there)
export const field = (object: unknown, key: string, defaultValue: unknown = null) => (contains(object, key) ? required(object, key) : defaultValue);

// The extension fields pycti copies to the top level before creating an object, when absent:
// pairs of [top-level key, extension key]
export const STIX_DOMAIN_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_stix_ids', 'stix_ids'],
  ['x_opencti_granted_refs', 'granted_refs'],
  ['x_opencti_workflow_id', 'workflow_id'],
  ['x_opencti_modified_at', 'modified_at'],
  ['opencti_upsert_operations', 'opencti_upsert_operations'],
];

export const backfillFromExtension = (object: StixObject, fields: [string, string][]) => {
  fields.forEach(([key, extensionKey]) => {
    if (!contains(object, key)) {
      setItem(object, key, getAttributeInExtension(extensionKey, object));
    }
  });
};

// The arguments every import_from_stix2 passes from its extras
export const extrasArguments = (extras: Kwargs) => ({
  custom_field_values: field(extras, 'custom_field_values'),
  createdBy: field(extras, 'created_by_id'),
  objectMarking: field(extras, 'object_marking_ids'),
  objectLabel: field(extras, 'object_label_ids'),
  externalReferences: field(extras, 'external_references_ids'),
  files: extras.files ?? null,
  filesMarkings: extras.filesMarkings ?? null,
  noTriggerImport: extras.noTriggerImport ?? null,
  embedded: extras.embedded ?? null,
});

// Run a creation mutation and return the created entity
export const mutate = async (context: ImportContext, document: string, root: string, input: Record<string, unknown>) => {
  const data = await context.client.query(document, { input });
  return data[root];
};

export type StixImporter = (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => Promise<any>;
