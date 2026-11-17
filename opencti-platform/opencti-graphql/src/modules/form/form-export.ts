import { FunctionalError } from '../../config/errors';
import { idsValuesRemap } from '../../database/stix-2-1-converter';
import { internalFindByIds } from '../../database/middleware-loader';
import { ENTITY_TYPE_GROUP } from '../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreObject } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityForm, type FormFieldDefinition, FormFieldType, type FormSchemaDefinition } from './form-types';
import { normalizeOptionId } from './form-utils';

// What a form schema refers to by id, and how the export treats it:
// - a marking or a group is written under its standard id, the same on every platform (the import resolves it back);
// - a user or an organization is never exported: the default that named it is left empty.
// `member` is an authorized member whose type is told by the entity itself: a group is kept, a user or an organization is not.
export type FormReferenceKind = 'marking' | 'group' | 'member';

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

const rewriteField = (field: FormFieldDefinition, resolve: FormReferenceResolver) => {
  const attributeName = field.attributeMapping?.attributeName;
  if (field.type === FormFieldType.ObjectMarking || attributeName === 'objectMarking') {
    const markings = convertDefault(field.defaultValue, 'marking', resolve);
    if (markings === undefined) {
      delete field.defaultValue;
    } else {
      field.defaultValue = markings;
    }
  } else if (field.type === FormFieldType.CreatedBy || IDENTITY_ATTRIBUTES.includes(attributeName)) {
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

// The standard id of a marking or a group, and nothing else: another kind of entity is not exported
const KIND_ENTITY_TYPES: Record<FormReferenceKind, string[]> = {
  marking: [ENTITY_TYPE_MARKING_DEFINITION],
  group: [ENTITY_TYPE_GROUP],
  member: [ENTITY_TYPE_GROUP],
};

// The references of a schema through the remap the other exports share: the internal ids become standard ids on export ('internal'),
// the standard ids become the internal ids of the platform on import ('stix'). A reference that is not exported, or that the platform
// does not know, is left out and counted.
export const convertFormSchemaIds = async (
  context: AuthContext,
  user: AuthUser,
  formSchema: FormSchemaDefinition,
  from: 'internal' | 'stix',
): Promise<{ schema: FormSchemaDefinition; unresolved: number }> => {
  // First pass: the ids to resolve, all in one lookup
  const ids = new Set<string>();
  rewriteFormSchemaReferences(formSchema, (_kind, id) => {
    ids.add(id);
    return id;
  });
  const resolved = ids.size > 0 ? await internalFindByIds(context, user, [...ids], { baseData: true, toMap: true, mapWithAllIds: true }) : {};
  const entities = resolved as unknown as { [id: string]: BasicStoreObject };
  // Second pass: the ids of the entities that are kept
  let unresolved = 0;
  const schema = rewriteFormSchemaReferences(formSchema, (kind, id) => {
    const entity = entities[id];
    const converted = entity && KIND_ENTITY_TYPES[kind].includes(entity.entity_type) ? idsValuesRemap([id], entities, from, true)[0] : undefined;
    if (!converted) {
      unresolved += 1;
      return null;
    }
    return converted;
  });
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
