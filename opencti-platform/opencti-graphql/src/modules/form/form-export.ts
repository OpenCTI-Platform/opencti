import { FunctionalError } from '../../config/errors';
import { idsValuesRemap } from '../../database/stix-2-1-converter';
import { internalFindByIds } from '../../database/middleware-loader';
import { ENTITY_TYPE_GROUP } from '../../schema/internalObject';
import { ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { isInternalId, isStixId } from '../../schema/schemaUtils';
import type { BasicStoreObject } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityForm, type FormFieldDefinition, FormFieldType, type FormSchemaDefinition } from './form-types';
import { normalizeOptionId } from './form-utils';

// What a form schema refers to by id, and how the export treats it:
// - a marking, a label or a group is written under its standard id, the same on every platform (the import resolves it back);
//   a label given by its value (a name, not an id) is kept as it is;
// - a user or an organization is never exported: the default that named it is left empty.
// `member` is an authorized member whose type is told by the entity itself: a group is kept, a user or an organization is not.
export type FormReferenceKind = 'marking' | 'label' | 'group' | 'member';

// The id to write for a reference, or null when the reference is not exported
export type FormReferenceResolver = (kind: FormReferenceKind, id: string) => string | null;

// The attributes mapped by a field whose default is an identity or a user
const IDENTITY_ATTRIBUTES = ['createdBy', 'objectAssignee', 'objectParticipant'];
// The members of an authorized members default that are not ids
const MEMBER_KEYWORDS = ['CREATORS', 'AUTHOR'];

type Option = unknown;

// An option is an id, or an object { value | id, label... }: the id is replaced, whatever else the option holds stays
const withId = (option: Option, id: string): Option => {
  if (typeof option !== 'object' || option === null) {
    return id;
  }
  return 'value' in option && option.value ? { ...option, value: id } : { ...option, id };
};

const convertOption = (option: Option, kind: FormReferenceKind, resolve: FormReferenceResolver): Option | null => {
  const id = normalizeOptionId(option);
  const converted = id ? resolve(kind, id) : null;
  return converted === null ? null : withId(option, converted);
};

// A default holds one option or a list of them; what cannot be exported is left out
const convertDefault = (value: unknown, kind: FormReferenceKind, resolve: FormReferenceResolver): unknown => {
  if (Array.isArray(value)) {
    return value.map((option) => convertOption(option, kind, resolve)).filter((option) => option !== null);
  }
  return value === undefined || value === null ? undefined : convertOption(value, kind, resolve) ?? undefined;
};

// A field whose default is an identity or a user: its default is never exported
const isIdentityField = (field: FormFieldDefinition) => field.type === FormFieldType.CreatedBy || IDENTITY_ATTRIBUTES.includes(field.attributeMapping?.attributeName);

const rewriteField = (field: FormFieldDefinition, resolve: FormReferenceResolver) => {
  const attributeName = field.attributeMapping?.attributeName;
  if (field.type === FormFieldType.ObjectMarking || attributeName === 'objectMarking') {
    const markings = convertDefault(field.defaultValue, 'marking', resolve);
    if (markings === undefined) {
      delete field.defaultValue;
    } else {
      field.defaultValue = markings;
    }
  } else if (field.type === FormFieldType.ObjectLabel || attributeName === 'objectLabel') {
    const labels = convertDefault(field.defaultValue, 'label', resolve);
    if (labels === undefined) {
      delete field.defaultValue;
    } else {
      field.defaultValue = labels;
    }
  } else if (isIdentityField(field)) {
    delete field.defaultValue;
  }
};

// A rule of the authorized members that cannot be exported is left out. A rule restricted to groups is left out as well when one
// of its groups is not exported: without its restriction the rule would give access to more members than it does here.
const rewriteMemberRule = (rule: Option, resolve: FormReferenceResolver): Option | null => {
  if (rule === null || rule === undefined) {
    return null;
  }
  if (typeof rule === 'object') {
    const legacyRule = rule as { type?: string; intersectionGroup?: string };
    if (legacyRule.type === 'CREATOR') {
      return rule;
    }
    if (legacyRule.type === 'AUTHOR_ORG') {
      if (!legacyRule.intersectionGroup) {
        return rule;
      }
      const group = resolve('group', legacyRule.intersectionGroup);
      return group === null ? null : { ...rule, intersectionGroup: group };
    }
  }
  const value = normalizeOptionId(rule);
  if (!value) {
    return null;
  }
  const restrictions = typeof rule === 'object' ? (rule as { groupsRestriction?: unknown }).groupsRestriction : undefined;
  const convertedRestrictions = Array.isArray(restrictions) ? restrictions.map((group) => convertOption(group, 'group', resolve)) : undefined;
  if (convertedRestrictions?.includes(null)) {
    return null;
  }
  const target = MEMBER_KEYWORDS.includes(value) ? value : resolve('member', value);
  if (target === null) {
    return null;
  }
  if (typeof rule !== 'object') {
    return target;
  }
  return { ...(withId(rule, target) as object), ...(convertedRestrictions ? { groupsRestriction: convertedRestrictions } : {}) };
};

// The schema of a form as the bundle carries it: the references it holds go through `resolve`. A copy, the schema given is not changed.
export const rewriteFormSchemaReferences = (formSchema: FormSchemaDefinition, resolve: FormReferenceResolver): FormSchemaDefinition => {
  const schema = structuredClone(formSchema);
  const relationshipFields = (schema.relationships ?? []).flatMap((relationship) => relationship.fields ?? []);
  // A stored form may hold what the schema of the forms does not check: only the fields that are objects are rewritten
  const fields = [...(schema.fields ?? []), ...relationshipFields].filter((field) => typeof field === 'object' && field !== null);
  fields.forEach((field) => rewriteField(field, resolve));
  if (schema.markings) {
    schema.markings = convertDefault(schema.markings, 'marking', resolve) as string[];
  }
  delete schema.createdByRef;
  const { draftDefaults } = schema;
  if (draftDefaults) {
    if (draftDefaults.objectAssignee) {
      draftDefaults.objectAssignee.defaults = [];
    }
    if (draftDefaults.objectParticipant) {
      draftDefaults.objectParticipant.defaults = [];
    }
    if (draftDefaults.author?.type === 'static') {
      // A static author is an identity: without it the form asks for the author like a form that has none
      const { isEditable, isRequired } = draftDefaults.author;
      draftDefaults.author = { type: 'none', isEditable, isRequired };
    }
    if (draftDefaults.authorizedMembers) {
      draftDefaults.authorizedMembers.defaults = (draftDefaults.authorizedMembers.defaults ?? [])
        .map((rule) => rewriteMemberRule(rule, resolve))
        .filter((rule) => rule !== null);
    }
  }
  return schema;
};

// A label is an id or a value (its name): only an id is converted
const isLabelValue = (kind: FormReferenceKind, id: string) => kind === 'label' && !isInternalId(id) && !isStixId(id);

// The standard id of a marking, a label or a group, and nothing else: another kind of entity is not exported
const KIND_ENTITY_TYPES: Record<FormReferenceKind, string[]> = {
  marking: [ENTITY_TYPE_MARKING_DEFINITION],
  label: [ENTITY_TYPE_LABEL],
  group: [ENTITY_TYPE_GROUP],
  member: [ENTITY_TYPE_GROUP],
};

// The entities a schema refers to, found in one lookup
const loadReferencedEntities = async (context: AuthContext, user: AuthUser, formSchema: FormSchemaDefinition) => {
  const ids = new Set<string>();
  rewriteFormSchemaReferences(formSchema, (kind, id) => {
    if (!isLabelValue(kind, id)) {
      ids.add(id);
    }
    return id;
  });
  const resolved = ids.size > 0 ? await internalFindByIds(context, user, [...ids], { baseData: true, toMap: true, mapWithAllIds: true }) : {};
  return resolved as unknown as { [id: string]: BasicStoreObject };
};

// The resolver of the references through the remap the other exports share: the internal ids become standard ids on export ('internal'),
// the standard ids become the internal ids of the platform on import ('stix'). A reference that is not exported, or that the platform
// does not know, gives null (`onUnresolved` is told).
const buildReferenceResolver = (entities: { [id: string]: BasicStoreObject }, from: 'internal' | 'stix', onUnresolved?: () => void): FormReferenceResolver => {
  return (kind, id) => {
    if (isLabelValue(kind, id)) {
      return id;
    }
    const entity = entities[id];
    const converted = entity && KIND_ENTITY_TYPES[kind].includes(entity.entity_type) ? idsValuesRemap([id], entities, from, true)[0] : undefined;
    if (!converted) {
      onUnresolved?.();
      return null;
    }
    return converted;
  };
};

// The references of a schema converted: what is not exported, or that the platform does not know, is left out and counted.
export const convertFormSchemaIds = async (
  context: AuthContext,
  user: AuthUser,
  formSchema: FormSchemaDefinition,
  from: 'internal' | 'stix',
): Promise<{ schema: FormSchemaDefinition; unresolved: number }> => {
  const entities = await loadReferencedEntities(context, user, formSchema);
  let unresolved = 0;
  const onUnresolved = () => {
    unresolved += 1;
  };
  const schema = rewriteFormSchemaReferences(formSchema, buildReferenceResolver(entities, from, onUnresolved));
  return { schema, unresolved };
};

export const exportFormSchema = async (context: AuthContext, user: AuthUser, formSchema: FormSchemaDefinition): Promise<FormSchemaDefinition> => {
  return (await convertFormSchemaIds(context, user, formSchema, 'internal')).schema;
};

// A form intake in the configuration of a bundle item. Its schema is a JSON object, not the string the entity stores.
// `active` is the state of the exported form: a form is imported inactive, whatever it was.
export const exportFormIntake = async (context: AuthContext, user: AuthUser, form: BasicStoreEntityForm) => {
  let formSchema: FormSchemaDefinition;
  try {
    formSchema = JSON.parse(form.form_schema);
  } catch {
    throw FunctionalError('The schema of a form intake is not a valid JSON', { id: form.internal_id, name: form.name });
  }
  return {
    name: form.name,
    description: form.description ?? '',
    form_schema: await exportFormSchema(context, user, formSchema),
    active: form.active,
  };
};

// The identity fields of a schema by id, the ones of the relationships under the id of their relationship
const identityFieldsOf = (schema: FormSchemaDefinition) => {
  const fields = new Map<string, FormFieldDefinition>();
  const isObject = (field: unknown): field is FormFieldDefinition => typeof field === 'object' && field !== null;
  (schema.fields ?? []).filter(isObject).filter(isIdentityField).forEach((field) => fields.set(`field:${field.id}`, field));
  (schema.relationships ?? []).forEach((relationship) => {
    (relationship.fields ?? []).filter(isObject).filter(isIdentityField).forEach((field) => fields.set(`${relationship.id}:${field.id}`, field));
  });
  return fields;
};

// The list of defaults of a setting the bundle holds empty: the one of the stored form, or none when it had none
const keepDefaults = (imported: { defaults?: unknown[] } | undefined, stored: { defaults?: unknown[] } | undefined) => {
  if (!imported || !stored) {
    return;
  }
  if (stored.defaults === undefined) {
    delete imported.defaults;
  } else {
    imported.defaults = stored.defaults;
  }
};

// The schema an overwrite writes: the schema of the bundle (as the ids of this platform), and what the bundle never carries, kept from the form
// that is overwritten: the users and the organizations it names (assignee and participant defaults, static author, `createdByRef`, the default of an
// identity field, the authorized members that are a user or an organization). So an export imported back on its own platform changes nothing, and
// on another platform the form keeps its own assignees and members. What the bundle carries (groups, markings, labels, flags) is the bundle's.
export const keepUserBoundSettings = async (
  context: AuthContext,
  user: AuthUser,
  stored: FormSchemaDefinition,
  imported: FormSchemaDefinition,
): Promise<FormSchemaDefinition> => {
  const schema = structuredClone(imported);
  if (stored.createdByRef !== undefined) {
    schema.createdByRef = stored.createdByRef;
  }
  const storedFields = identityFieldsOf(stored);
  identityFieldsOf(schema).forEach((field, key) => {
    const storedField = storedFields.get(key);
    if (storedField && storedField.defaultValue !== undefined) {
      field.defaultValue = storedField.defaultValue;
    }
  });
  const storedDefaults = stored.draftDefaults;
  const { draftDefaults } = schema;
  if (!storedDefaults || !draftDefaults) {
    return schema;
  }
  keepDefaults(draftDefaults.objectAssignee, storedDefaults.objectAssignee);
  keepDefaults(draftDefaults.objectParticipant, storedDefaults.objectParticipant);
  if (draftDefaults.author?.type === 'none' && storedDefaults.author?.type === 'static') {
    // The bundle cannot tell a form with no author from a form whose static author was not exported: the author of the form stays, under the flags of the bundle
    const { isEditable, isRequired } = draftDefaults.author;
    draftDefaults.author = { ...storedDefaults.author, isEditable, isRequired };
  }
  const storedRules = storedDefaults.authorizedMembers?.defaults ?? [];
  if (draftDefaults.authorizedMembers && storedRules.length > 0) {
    // The rules of the stored form that the export leaves out are kept where they are; the others are the ones of the bundle, in the order of the form
    const resolve = buildReferenceResolver(await loadReferencedEntities(context, user, stored), 'internal');
    const bundleRules = [...(draftDefaults.authorizedMembers.defaults ?? [])];
    const rules = storedRules.flatMap((rule) => (rewriteMemberRule(rule, resolve) === null ? [rule] : bundleRules.splice(0, 1)));
    draftDefaults.authorizedMembers.defaults = [...rules, ...bundleRules];
  } else if (draftDefaults.authorizedMembers && storedDefaults.authorizedMembers?.defaults === undefined && draftDefaults.authorizedMembers.defaults?.length === 0) {
    delete (draftDefaults.authorizedMembers as { defaults?: unknown[] }).defaults;
  }
  return schema;
};
