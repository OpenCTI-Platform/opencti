import { FunctionalError } from '../../config/errors';
import { internalLoadById } from '../../database/middleware-loader';
import { ALLOWED_EMBEDDED_IMAGE_MIME_TYPE_SET, DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES, DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES } from '../../database/markdown-embedded-images';
import { collectTempImageTokensFromDescriptionFields, rewriteTempImageTokensInDescriptions } from '../../database/middlewareEmbeddedImages';
import { INPUT_ASSIGNEE, INPUT_CREATED_BY, INPUT_EXTERNAL_REFS, INPUT_GRANTED_REFS, INPUT_KILLCHAIN, INPUT_LABELS, INPUT_MARKINGS, INPUT_PARTICIPANT } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../user/user-types';
import { isNotEmptyField } from '../../database/utils';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { isStixDomainObject, isStixDomainObjectIdentity } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { StoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import type { FormSchemaDefinition } from './form-types';
import { PENDING_EXTERNAL_REFERENCE } from './form-pending-marker';

/**
 * Deferred-creation contract of a Form Intake submission.
 *
 * Objects the user prepared on the fly are sent with the submission instead of being created
 * beforehand. They live in two places of `values`:
 *  - roots: `mainEntityLookupPending` and `additional_<id>_lookup_pending`, always materialised;
 *  - pool: `pendingObjects`, only materialised when a root references them.
 * An object may be referenced by its client-local `id`. The legacy `{ entityType, input }` shape
 * (no id, no refs, no files) stays valid and is copied as before.
 *
 * The payload comes from the client, nothing in it is trusted:
 *  - validatePendingPayload checks its shape, its limits and its references, synchronously;
 *  - validatePendingRoots checks the roots against the form schema (field type, lookup, creation allowed, amount);
 *  - only the attributes a user can set are copied onto the objects (copyAttributes).
 *
 * References of an object (`refs`, or ids left in its `input` for the existing-only ones):
 *  - createdBy, objectMarking, killChainPhases, objectAssignee, objectParticipant: existing objects only,
 *    loaded with the submitter rights. The STIX converter writes assignees and participants in the OpenCTI extension
 *    (assignee_ids, participant_ids) and pycti turns them back into objectAssignee / objectParticipant on import
 *    (the report, case and task entities), so they reach the created object.
 *  - objectLabel, externalReferences: existing objects or pooled objects created on submission.
 * Fields of the creation dialogs this contract does not carry (`objects`, `caseTemplates`, `content_mapping`, `authorized_members`,
 * `customFieldValues`) are rejected when filled, they are never dropped silently. So is `objectOrganization`, in `input` and in `refs`:
 * sharing an object with organizations needs KNOWLEDGE_KNUPDATE_KNORGARESTRICT, which the form import (KNUPDATE only) does not grant.
 */
export type PendingRef = { existing: string } | { pending: string };

// Limits of the payload, it comes from the client. They are checked before anything is read or loaded.
export const MAX_PENDING_UPLOAD_BYTES = 40 * 1024 * 1024; // decoded size of all the uploads together
export const MAX_PENDING_ROOTS = 1000; // objects created in the lookup fields
export const MAX_PENDING_POOL = 200; // pooled labels and external references
export const MAX_PENDING_REFS_PER_OBJECT = 100; // references of one object, all kinds together
export const MAX_PENDING_REFS_TOTAL = 2000; // references of the whole submission, bounds the existing objects loaded

export interface PendingFile {
  name: string;
  mime_type?: string;
  uploadIndex: number; // index in the `files` uploads of the submission
  embedded?: boolean; // markdown image of a description (pasted in the editor), not an attached file
}

export interface PendingObject {
  id?: string;
  entityType: string;
  input: Record<string, any>;
  refs?: Partial<Record<PendingRefKey, PendingRef | PendingRef[]>>;
  files?: PendingFile[];
}

// Uploads of the submission, already read: `data` is base64.
export interface PendingUpload {
  filename: string;
  mimetype: string;
  data: string;
}

const REF_KEYS = [INPUT_CREATED_BY, INPUT_MARKINGS, INPUT_LABELS, INPUT_EXTERNAL_REFS, INPUT_KILLCHAIN, INPUT_ASSIGNEE, INPUT_PARTICIPANT] as const;
type PendingRefKey = typeof REF_KEYS[number];

// What each kind of reference points to. Only labels and external references can be pending (created on submission).
const REF_TARGETS: Record<PendingRefKey, { isTarget: (type: string) => boolean; pendingType?: string }> = {
  [INPUT_CREATED_BY]: { isTarget: isStixDomainObjectIdentity },
  [INPUT_MARKINGS]: { isTarget: (type) => type === ENTITY_TYPE_MARKING_DEFINITION },
  [INPUT_LABELS]: { isTarget: (type) => type === ENTITY_TYPE_LABEL, pendingType: ENTITY_TYPE_LABEL },
  [INPUT_EXTERNAL_REFS]: { isTarget: (type) => type === ENTITY_TYPE_EXTERNAL_REFERENCE, pendingType: ENTITY_TYPE_EXTERNAL_REFERENCE },
  [INPUT_KILLCHAIN]: { isTarget: (type) => type === ENTITY_TYPE_KILL_CHAIN_PHASE },
  [INPUT_ASSIGNEE]: { isTarget: (type) => type === ENTITY_TYPE_USER },
  [INPUT_PARTICIPANT]: { isTarget: (type) => type === ENTITY_TYPE_USER },
};
// References stored as { internal_id, standard_id }, the others carry their own attributes.
const ID_REF_KEYS: readonly string[] = [INPUT_MARKINGS, INPUT_ASSIGNEE, INPUT_PARTICIPANT];
const POOLED_TYPES = Object.values(REF_TARGETS).flatMap((target) => (target.pendingType ? [target.pendingType] : []));

// The creation dialogs leave these references in the input, as ids. Only existing objects can be referenced.
const EXISTING_ONLY_INPUT_REFS = [INPUT_ASSIGNEE, INPUT_PARTICIPANT] as const;

// Input fields of the creation dialogs that the contract does not carry: rejected when filled, never dropped silently.
// objectOrganization (sharing) needs its own capability, which a form submission does not grant: it is also refused in refs.
const UNSUPPORTED_INPUT_FIELDS = ['objects', 'caseTemplates', 'content_mapping', 'authorized_members', 'restricted_members', 'customFieldValues', INPUT_GRANTED_REFS];

const isRootKey = (key: string) => key === 'mainEntityLookupPending' || key.endsWith('_lookup_pending');

const toArray = <T>(value: T | T[] | undefined | null): T[] => (value === undefined || value === null ? [] : [value].flat() as T[]);

export const getPendingRoots = (values: Record<string, any>): PendingObject[] => {
  return Object.keys(values)
    .filter(isRootKey)
    .flatMap((key) => toArray<PendingObject>(values[key]));
};

// The references of a pending object: its `refs` plus the existing-only ones left in its input (ids).
export const getPendingRefs = (pending: PendingObject): Partial<Record<PendingRefKey, PendingRef | PendingRef[]>> => {
  const refs = { ...pending.refs };
  for (const key of EXISTING_ONLY_INPUT_REFS) {
    const ids = toArray<string>(pending.input[key]).filter((id) => id !== '');
    if (ids.length > 0 && refs[key] === undefined) refs[key] = ids.map((existing) => ({ existing }));
  }
  return refs;
};

/**
 * Input fields of the entity-creation mutations that are never copied onto the pending entity:
 *  - references (createdBy, objectMarking, ...), carried by `refs` instead,
 *  - file uploads, carried by `files` instead,
 *  - mutation metadata (type, update, clientMutationId, ...) and the workflow status, set by the platform.
 * `objects`, `caseTemplates` and `content_mapping` are not supported, validatePendingPayload rejects them when filled.
 */
// Options of the creation dialogs that ask the platform to create more objects (the observables of an indicator pattern,
// the indicator of an observable). They are not attributes: ignored when off, rejected when on (not supported in a form).
const UNSUPPORTED_TOGGLES = ['createObservables', 'createIndicator'];

const PENDING_IGNORED_INPUT_FIELDS = new Set<string>([
  'createdBy', 'objectMarking', 'objectLabel', 'objectOrganization',
  'objectAssignee', 'objectParticipant', 'externalReferences', 'killChainPhases',
  'objects', 'caseTemplates', 'content_mapping',
  'file', 'fileMarkings', 'files', 'filesMarkings', 'x_opencti_files', 'embedded', 'noTriggerImport',
  'update', 'upsertOperations', 'clientMutationId', 'type', 'x_opencti_workflow_id',
  ...UNSUPPORTED_TOGGLES,
]);

// Attributes the platform owns: a client can never set them on an object (on top of the ones that cannot be updated).
const PENDING_INTERNAL_ATTRIBUTES = new Set<string>([
  'creator_id', 'x_opencti_stix_ids', 'restricted_members', 'authorized_members_activation_date', 'authorized_authorities', 'grantable_groups',
  'default_dashboard', 'default_hidden_types', 'custom_field_values', 'pir_information', 'metrics', 'opinions_metrics', 'coverage_information',
  'history_changes', 'errors', 'draft_context', 'lastEventId', 'x_opencti_graph_data',
]);

const isEmptyInput = (value: unknown) => value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0);

const isScalarOrScalarArray = (value: unknown): boolean => {
  const valueType = typeof value;
  if (valueType === 'string' || valueType === 'number' || valueType === 'boolean') return true;
  return Array.isArray(value) && value.every((item) => ['string', 'number', 'boolean'].includes(typeof item));
};

// Only the real attributes of the entity type that a user can set are copied. A reference of the type is carried by `refs`.
const isCopyableAttribute = (entityType: string, key: string): boolean => {
  if (schemaRelationsRefDefinition.getRelationRef(entityType, key)) return false;
  const attribute = schemaAttributesDefinition.getAttribute(entityType, key);
  if (!attribute || attribute.update === false || PENDING_INTERNAL_ATTRIBUTES.has(key)) {
    throw FunctionalError(`This attribute cannot be set when creating an object in a form: ${key}`, { entityType, attribute: key });
  }
  return true;
};

// Mutation inputs send hashes as [{ algorithm, hash }], the store keeps { [algorithm]: hash }.
const copyAttributes = (target: Record<string, any>, attributes: Record<string, any>, entityType: string) => {
  for (const [key, value] of Object.entries(attributes)) {
    if (PENDING_IGNORED_INPUT_FIELDS.has(key) || isEmptyInput(value) || !isCopyableAttribute(entityType, key)) continue;
    if (key === 'hashes' && Array.isArray(value)) {
      const hashes = Object.fromEntries(value.filter((h) => h?.algorithm && h?.hash).map((h) => [h.algorithm, h.hash]));
      if (Object.keys(hashes).length > 0) target.hashes = hashes;
    } else if (isScalarOrScalarArray(value)) {
      target[key] = value;
    }
  }
};

/**
 * SDO mutations: input = { name, description, aliases, ... }
 * SCO mutations: input is flat: { type, x_opencti_description, IPv4Addr: { value }, ... }
 * The entity type comes from the pending object only, set once the attributes are copied.
 */
const buildPendingAttributes = (pending: PendingObject): Record<string, any> => {
  const entity: Record<string, any> = {};
  const { input, entityType } = pending;
  const isObservableInput = typeof input.type === 'string' && !('name' in input);
  if (!isObservableInput) {
    copyAttributes(entity, input, entityType);
  } else {
    // Observables use x_opencti_description (not description) in the store / STIX model.
    if (input.x_opencti_description) entity.x_opencti_description = input.x_opencti_description;
    if (input.x_opencti_score !== undefined && input.x_opencti_score !== null) {
      entity.x_opencti_score = input.x_opencti_score;
    }
    // The observable-specific attributes are nested under the type key (the only nested
    // object, e.g. 'IPv4Addr', 'DomainName', 'StixFile'), still skipping refs/files.
    const obsTypeKey = Object.keys(input).find((key) => key !== 'type'
      && !PENDING_IGNORED_INPUT_FIELDS.has(key)
      && typeof input[key] === 'object'
      && input[key] !== null
      && !Array.isArray(input[key]));
    if (obsTypeKey) {
      copyAttributes(entity, input[obsTypeKey], entityType);
      // Use the observable value as a display name so standard id generation / STIX conversion can work.
      if (entity.value !== undefined && entity.name === undefined) {
        entity.name = entity.value;
      }
    }
  }
  entity.entity_type = entityType;
  return entity;
};

/**
 * Attach the uploaded files of a pending object to its store entity.
 * Regular files are attached as they are. Markdown images (embedded) replace the temp image tokens of the
 * description fields by data URIs: the import turns them into embedded files like the creation mutations do,
 * with the same mime type and size limits.
 * Ordering contract: the embedded files are given in the order of the first appearance of their token in the
 * description fields (the order of collectTempImageTokensFromDescriptionFields, a token used twice counts once),
 * and there must be exactly one per token. The mime type checked is the one of the upload, not the one the client declares.
 */
const applyPendingFiles = (entity: Record<string, any>, files: PendingFile[] | undefined, uploads: PendingUpload[]) => {
  const resolved = (files ?? []).map((file) => {
    const upload = uploads[file.uploadIndex];
    return {
      embedded: file.embedded === true,
      name: file.name || upload.filename,
      data: upload.data,
      mime_type: file.mime_type || upload.mimetype || 'application/octet-stream',
      uploadMimeType: (upload.mimetype ?? '').toLowerCase(),
    };
  });
  const regular = resolved.filter((file) => !file.embedded).map(({ name, data, mime_type }) => ({ name, data, mime_type }));
  if (regular.length > 0) entity.x_opencti_files = regular;
  const images = resolved.filter((file) => file.embedded);
  const tokens = collectTempImageTokensFromDescriptionFields(entity);
  if (images.length !== tokens.length) {
    throw FunctionalError('The embedded images do not match the image references of the description', { images: images.length, references: tokens.length });
  }
  if (images.length === 0) return;
  const tokenToUri = new Map<string, string>();
  let totalSize = 0;
  images.forEach((image, index) => {
    const size = Buffer.byteLength(image.data, 'base64');
    totalSize += size;
    if (!ALLOWED_EMBEDDED_IMAGE_MIME_TYPE_SET.has(image.uploadMimeType)) {
      throw FunctionalError('Unsupported markdown embedded image mime type', { mimeType: image.uploadMimeType, name: image.name });
    }
    if (size > DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES || totalSize > DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES) {
      throw FunctionalError('Markdown embedded image is too large', { name: image.name });
    }
    tokenToUri.set(tokens[index], `data:${image.uploadMimeType};base64,${image.data}`);
  });
  rewriteTempImageTokensInDescriptions(entity, tokenToUri);
};

// A pooled external reference: its attributes, its files and the markdown images of its description.
const materializePooledReference = (pooled: PendingObject, uploads: PendingUpload[]) => {
  const { entity_type: _type, ...reference } = buildPendingAttributes(pooled);
  applyPendingFiles(reference, pooled.files, uploads);
  return reference;
};

// Indexes of the uploads the pending objects point to (roots and pool), only these are read.
export const getPendingUploadIndexes = (values: Record<string, any>): number[] => {
  const objects = [...getPendingRoots(values), ...toArray<PendingObject>(values.pendingObjects)];
  return [...new Set(objects.flatMap((object) => (object.files ?? []).map((file) => file.uploadIndex)))].sort((a, b) => a - b);
};

const isObject = (value: unknown): value is Record<string, any> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isFilledString = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

// Shape of an object sent by the client, checked before anything reads it.
const validatePendingObjectShape = (object: unknown): void => {
  if (!isObject(object)) throw FunctionalError('An object created in a form must be an object');
  const { entityType, input, id, refs, files } = object;
  if (!isFilledString(entityType)) throw FunctionalError('An object created in a form requires an entityType');
  if (!isObject(input)) throw FunctionalError('An object created in a form requires an input object', { entityType });
  if (id !== undefined && !isFilledString(id)) throw FunctionalError('The id of an object created in a form must be a string', { entityType });
  if (refs !== undefined && !isObject(refs)) throw FunctionalError('The refs of an object created in a form must be an object', { entityType });
  if (files !== undefined && !Array.isArray(files)) throw FunctionalError('The files of an object created in a form must be a list', { entityType });
  for (const field of UNSUPPORTED_INPUT_FIELDS) {
    if (!isEmptyInput(input[field])) {
      throw FunctionalError(`This field is not supported when creating an object in a form: ${field}`, { entityType, field });
    }
  }
  for (const field of UNSUPPORTED_TOGGLES) {
    if (input[field] === true) {
      throw FunctionalError(`This option is not supported when creating an object in a form: ${field}`, { entityType, field });
    }
  }
  if (isObject(refs) && !isEmptyInput(refs[INPUT_GRANTED_REFS])) {
    throw FunctionalError(`This field is not supported when creating an object in a form: ${INPUT_GRANTED_REFS}`, { entityType, field: INPUT_GRANTED_REFS });
  }
  for (const field of EXISTING_ONLY_INPUT_REFS) {
    if (!isEmptyInput(input[field]) && !toArray(input[field]).every(isFilledString)) {
      throw FunctionalError('This field must contain the ids of existing objects', { entityType, field });
    }
  }
  for (const file of files ?? []) {
    const valid = isObject(file)
      && (file.name === undefined || typeof file.name === 'string')
      && (file.mime_type === undefined || typeof file.mime_type === 'string')
      && (file.embedded === undefined || typeof file.embedded === 'boolean');
    if (!valid) throw FunctionalError('Invalid file of an object created in a form', { entityType });
  }
};

// A pooled label needs a value, a pooled external reference a source name.
const POOLED_REQUIRED_ATTRIBUTE: Record<string, string> = { [ENTITY_TYPE_LABEL]: 'value', [ENTITY_TYPE_EXTERNAL_REFERENCE]: 'source_name' };

const validatePendingRef = (key: string, ref: unknown): void => {
  const target = isObject(ref) && Object.keys(ref).length === 1 ? ref.existing ?? ref.pending : undefined;
  if (!isFilledString(target)) throw FunctionalError('Invalid pending ref', { key });
};

/**
 * Structural checks of the pending payload. Rejects the whole submission on the first problem,
 * the frontend keeps the user input. Everything is checked synchronously, before any upload is read
 * or any reference is loaded.
 */
export const validatePendingPayload = (values: Record<string, any>, uploadCount: number): void => {
  for (const key of Object.keys(values).filter(isRootKey)) {
    if (values[key] != null && typeof values[key] !== 'object') throw FunctionalError('Invalid objects created in a form', { field: key });
  }
  if (values.pendingObjects != null && !Array.isArray(values.pendingObjects)) {
    throw FunctionalError('The pending objects of a form must be a list');
  }
  const roots = getPendingRoots(values);
  const pool = toArray<PendingObject>(values.pendingObjects);
  if (roots.length > MAX_PENDING_ROOTS) throw FunctionalError('Too many objects created in the form', { max: MAX_PENDING_ROOTS });
  if (pool.length > MAX_PENDING_POOL) throw FunctionalError('Too many labels and external references created in the form', { max: MAX_PENDING_POOL });
  [...roots, ...pool].forEach(validatePendingObjectShape);
  const byId = new Map<string, PendingObject>();
  for (const object of [...roots, ...pool]) {
    if (object.id === undefined) continue;
    if (byId.has(object.id)) throw FunctionalError('Duplicate pending object id', { id: object.id });
    byId.set(object.id, object);
  }
  for (const object of pool) {
    if (!POOLED_TYPES.includes(object.entityType)) {
      throw FunctionalError('Only labels and external references can be pooled', { id: object.id, entityType: object.entityType });
    }
    if (object.id === undefined) throw FunctionalError('A pooled pending object requires an id', { entityType: object.entityType });
    if (object.refs) throw FunctionalError('A pooled pending object cannot have refs', { id: object.id });
    const required = POOLED_REQUIRED_ATTRIBUTE[object.entityType];
    if (!isFilledString(object.input[required])) {
      throw FunctionalError('A pooled pending object lacks a required attribute', { id: object.id, entityType: object.entityType, attribute: required });
    }
  }
  let totalRefs = 0;
  for (const object of roots) {
    const objectRefs = getPendingRefs(object);
    const refCount = Object.values(objectRefs).reduce((count, refs) => count + toArray(refs).length, 0);
    if (refCount > MAX_PENDING_REFS_PER_OBJECT) {
      throw FunctionalError('Too many references on an object created in the form', { max: MAX_PENDING_REFS_PER_OBJECT });
    }
    totalRefs += refCount; // pooled objects have no refs
    if (totalRefs > MAX_PENDING_REFS_TOTAL) {
      throw FunctionalError('Too many references in the objects created in the form', { max: MAX_PENDING_REFS_TOTAL });
    }
    for (const [key, value] of Object.entries(objectRefs)) {
      if (!(REF_KEYS as readonly string[]).includes(key)) throw FunctionalError('Unsupported pending ref', { key });
      const refs = toArray<PendingRef>(value);
      if (key === INPUT_CREATED_BY && refs.length > 1) throw FunctionalError('An object has a single author', { key });
      for (const ref of refs) {
        validatePendingRef(key, ref);
        if ('pending' in ref) {
          // Authors are never created by a form: createdBy has no pending target type.
          const target = byId.get(ref.pending);
          if (!target) throw FunctionalError('Pending ref not found in submission', { key, id: ref.pending });
          if (target.entityType !== REF_TARGETS[key as PendingRefKey].pendingType) {
            throw FunctionalError('Pending ref cannot target this entity type', { key, id: ref.pending, entityType: target.entityType });
          }
        }
      }
    }
  }
  for (const object of [...roots, ...pool]) {
    for (const file of object.files ?? []) {
      if (!Number.isInteger(file.uploadIndex) || file.uploadIndex < 0 || file.uploadIndex >= uploadCount) {
        throw FunctionalError('Pending file refers to a missing upload', { name: file.name, uploadIndex: file.uploadIndex });
      }
    }
  }
  const referenced = new Set(getPendingUploadIndexes(values));
  for (let index = 0; index < uploadCount; index += 1) {
    if (!referenced.has(index)) throw FunctionalError('An upload is not referenced by any object created in the form', { uploadIndex: index });
  }
};

const isSameOrSubType = (type: string, parent: string) => type === parent || schemaTypesDefinition.isTypeIncludedIn(type, parent);

// Types a form can create: concrete STIX domain objects and observables, never meta, internal or
// relationship types nor the abstract parents (Identity, Location, Container...).
const isCreatableType = (type: string) => {
  return (isStixDomainObject(type) || isStixCyberObservable(type)) && !schemaTypesDefinition.hasChildren(type);
};

/**
 * The pending payload comes from the client: the roots must match what the form schema allows,
 * like the existing entities selected in the same field. Without it a form user could create any type
 * of object through any lookup of any form.
 */
export const validatePendingRoots = (schema: FormSchemaDefinition, values: Record<string, any>): void => {
  for (const key of Object.keys(values).filter(isRootKey)) {
    const roots = toArray<PendingObject>(values[key]);
    if (roots.length === 0) continue;
    const additional = schema.additionalEntities?.find((entity) => `additional_${entity.id}_lookup_pending` === key);
    if (key !== 'mainEntityLookupPending' && !additional) {
      throw FunctionalError('Unknown field for objects created in a form', { field: key });
    }
    const field = additional
      ? { ...additional, existing: values[`additional_${additional.id}_lookup`] }
      : {
          entityType: schema.mainEntityType,
          lookup: schema.mainEntityLookup,
          disableCreation: schema.mainEntityDisableCreation,
          multiple: schema.mainEntityMultiple,
          existing: values.mainEntityLookup,
        };
    if (!field.lookup) {
      throw FunctionalError('Objects cannot be created in a field that is not an entity lookup', { field: key });
    }
    if (field.disableCreation) {
      throw FunctionalError('Objects cannot be created in this field, only existing ones can be selected', { field: key });
    }
    for (const root of roots) {
      if (!isSameOrSubType(root.entityType, field.entityType) || !isCreatableType(root.entityType)) {
        throw FunctionalError('This field cannot create an object of this type', { field: key, entityType: root.entityType, expected: field.entityType });
      }
    }
    if (!field.multiple && roots.length + toArray(field.existing).filter(isNotEmptyField).length > 1) {
      throw FunctionalError('This field accepts a single object', { field: key });
    }
  }
};

const isPendingRef = (node: any): node is { pending: string } => {
  return typeof node === 'object' && node !== null && !Array.isArray(node)
    && Object.keys(node).length === 1 && typeof node.pending === 'string';
};

/**
 * Direct label / external reference fields can hold `{ pending: id }` entries next to the usual
 * values (label names, external reference ids). Replace them by the pooled label name or the pooled
 * external reference attributes, so the field converters handle them like any other value.
 * Pending roots and the pool are left untouched (their refs are resolved by materializePendingRoots).
 */
export const resolvePendingFieldRefs = (values: Record<string, any>, uploads: PendingUpload[] = []): Record<string, any> => {
  const pool = new Map(toArray<PendingObject>(values.pendingObjects).map((object) => [object.id, object]));
  const resolve = (id: string) => {
    const target = pool.get(id);
    if (target?.entityType === ENTITY_TYPE_LABEL) return target.input.value;
    if (target?.entityType === ENTITY_TYPE_EXTERNAL_REFERENCE) {
      // Marked (not enumerable) so the field converter only accepts the objects produced here
      return Object.defineProperty(materializePooledReference(target, uploads), PENDING_EXTERNAL_REFERENCE, { value: true });
    }
    throw FunctionalError('Pending field ref must target a pooled label or external reference', { id });
  };
  const walk = (node: any): any => {
    if (Array.isArray(node)) return node.map(walk);
    if (isPendingRef(node)) return resolve(node.pending);
    if (typeof node === 'object' && node !== null) {
      return Object.fromEntries(Object.entries(node).map(([key, value]) => [key, walk(value)]));
    }
    return node;
  };
  const isPendingKey = (key: string) => key === 'pendingObjects' || isRootKey(key);
  return Object.fromEntries(Object.entries(values).map(([key, value]) => [key, isPendingKey(key) ? value : walk(value)]));
};

// Objects created in the form that carry a kill chain phase: the import upserts the phase, which has its own right.
export const countPendingKillChainPhases = (values: Record<string, any>): number => {
  return getPendingRoots(values).filter((root) => toArray(root.refs?.[INPUT_KILLCHAIN]).length > 0).length;
};

export const countPendingLabels = (values: Record<string, any>): number => {
  return toArray<PendingObject>(values.pendingObjects).filter((object) => object.entityType === ENTITY_TYPE_LABEL).length;
};

/**
 * Reads the given uploads (all by default) into memory as base64, one after the other. The result is indexed
 * like the uploads, the ones that are not asked for stay empty. The decoded size of the whole is capped.
 */
export const readUploads = async (uploads: any[] | null | undefined, indexes?: Iterable<number>): Promise<PendingUpload[]> => {
  const list = uploads ?? [];
  const result: PendingUpload[] = [];
  let totalBytes = 0;
  for (const index of indexes ?? list.keys()) {
    const { filename, mimetype, createReadStream } = await list[index];
    const chunks: Buffer[] = [];
    for await (const chunk of createReadStream()) {
      totalBytes += chunk.length;
      if (totalBytes > MAX_PENDING_UPLOAD_BYTES) {
        throw FunctionalError('The uploads of the form are too large', { maxBytes: MAX_PENDING_UPLOAD_BYTES });
      }
      chunks.push(chunk);
    }
    result[index] = { filename, mimetype, data: Buffer.concat(chunks).toString('base64') };
  }
  return result;
};

/**
 * Build the store entities of the pending roots with their references resolved.
 * Existing refs are loaded with the submitter rights, so a reference the user cannot read is rejected.
 */
export const materializePendingRoots = async (
  context: AuthContext,
  user: AuthUser,
  roots: PendingObject[],
  values: Record<string, any>,
  uploads: PendingUpload[],
): Promise<StoreEntity[]> => {
  const pool = new Map(toArray<PendingObject>(values.pendingObjects).map((object) => [object.id, object]));
  // One load per id and per call: many objects of a submission share the same markings, labels or authors.
  const loads = new Map<string, Promise<any>>();
  const loadExisting = async (key: PendingRefKey, id: string) => {
    if (!loads.has(id)) loads.set(id, internalLoadById<any>(context, user, id));
    const loaded = await loads.get(id);
    if (!loaded || !REF_TARGETS[key].isTarget(loaded.entity_type)) {
      throw FunctionalError('Pending ref does not target an accessible entity of the expected type', { key, id });
    }
    return loaded;
  };
  const resolveRefs = async (key: PendingRefKey, refs: PendingRef[]) => {
    return Promise.all(refs.map(async (ref) => {
      if ('existing' in ref) return loadExisting(key, ref.existing);
      const pooled = pool.get(ref.pending) as PendingObject; // presence and type checked by validatePendingPayload
      return key === INPUT_LABELS ? pooled.input : materializePooledReference(pooled, uploads);
    }));
  };

  return Promise.all(roots.map(async (pending) => {
    const entity = buildPendingAttributes(pending);
    applyPendingFiles(entity, pending.files, uploads);
    for (const [key, refs] of Object.entries(getPendingRefs(pending)) as [PendingRefKey, PendingRef | PendingRef[]][]) {
      const resolved = await resolveRefs(key, toArray(refs));
      if (key === INPUT_CREATED_BY) {
        entity[key] = { internal_id: resolved[0].internal_id, standard_id: resolved[0].standard_id };
      } else if (ID_REF_KEYS.includes(key)) {
        entity[key] = resolved.map((r) => ({ internal_id: r.internal_id, standard_id: r.standard_id }));
      } else if (key === INPUT_LABELS) {
        entity[key] = resolved.map((r) => ({ value: r.value }));
      } else {
        entity[key] = resolved; // external references and kill chain phases carry their own attributes
      }
    }
    return entity as StoreEntity;
  }));
};

/**
 * The STIX converter only writes the descriptive attributes of an external reference. The files of the
 * external references created on submission travel next to them (x_opencti_files with their data), the
 * import attaches them to the external reference.
 */
export const withPendingExternalReferenceFiles = <T extends Record<string, any>>(stix: T, entity: Record<string, any>): T => {
  const references = entity[INPUT_EXTERNAL_REFS];
  if (Array.isArray(references) && Array.isArray(stix.external_references)) {
    references.forEach((reference, index) => {
      const files = (reference?.x_opencti_files ?? []).filter((file: Record<string, any>) => file?.data);
      if (files.length > 0 && stix.external_references[index]) {
        stix.external_references[index].x_opencti_files = files;
      }
    });
  }
  return stix;
};
