import * as R from 'ramda';
import { elAttributeValues } from '../database/engine';
import { getRegisteredTypeFromIndexedName, schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';
import { buildPagination } from '../database/utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { Attribute, QueryRuntimeAttributesArgs, TypeAttribute } from '../generated/graphql';
import { INTERNAL_ATTRIBUTES } from './attribute-utils';
import { getCustomFieldDefinitionsForEntityType, getDynamicTypeAttributeForEntityType } from '../modules/customField/custom-field-cache';
import { type EntitySettingSchemaAttribute, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import type { BasicStoreEntityEntitySetting } from '../modules/entitySetting/entitySetting-types';
import { getEntitySettingSchemaAttributes } from '../modules/entitySetting/entitySetting-attributeUtils';
import { FunctionalError, UNSUPPORTED_ERROR } from '../config/errors';
import type { RefAttribute } from '../schema/attribute-definition';
import { INPUT_EXTERNAL_REFS, INPUT_MARKINGS } from '../schema/general';

export interface DefaultValue {
  id: string;
  name: string;
}

// -- ATTRIBUTES --

export const getRuntimeAttributeValues = (context: AuthContext, user: AuthUser, opts: QueryRuntimeAttributesArgs = {} as QueryRuntimeAttributesArgs) => {
  const { attributeName } = opts;
  return elAttributeValues(context, user, attributeName, opts);
};

export const getSchemaAttributeNames = async (context: AuthContext, user: AuthUser, elementTypes: string[]) => {
  const attributes = R.uniq(elementTypes.map((type) => schemaAttributesDefinition.getAttributeNames(type)).flat());
  const sortByLabel = R.sortBy(R.toLower);
  const finalResult = R.pipe(
    sortByLabel,
    R.map((n) => ({ node: { id: n, key: elementTypes[0], value: n } })),
  )(attributes);
  // Inject custom field names dynamically for dashboard widgets and distribution queries
  for (const type of elementTypes) {
    const customFieldDefs = await getCustomFieldDefinitionsForEntityType(context, user, type);
    for (const cfDef of customFieldDefs) {
      if (!finalResult.some((r: any) => r.node.id === cfDef.name)) {
        finalResult.push({ node: { id: cfDef.name, key: type, value: cfDef.name } });
      }
    }
  }
  return buildPagination<Attribute>(0, null, finalResult, finalResult.length);
};

export const getSchemaAttributes = async (context: AuthContext, user: AuthUser, entityType?: string | null) => {
  const registeredTypes = schemaAttributesDefinition.getRegisteredTypes();
  // A single type can be asked, so an API client does not load the whole schema each time.
  // Only an absent filter returns every type. A given type is matched whatever its letter case
  // (malware is Malware); a name of no registered type, even empty, is an error rather than an
  // empty list, so that a typo is not taken for a type without attributes.
  let types = registeredTypes;
  if (!R.isNil(entityType)) {
    const registeredType = registeredTypes.includes(entityType) ? entityType : getRegisteredTypeFromIndexedName(entityType.toLowerCase());
    if (!registeredType) {
      throw FunctionalError('Unknown entity type', { entityType });
    }
    types = [registeredType];
  }

  // Every relationship type and every observable inherit the same entity setting: its
  // effective attributes (and the lookup of its ref default values) are computed once per call.
  const effectiveBySetting = new Map<string, Promise<EntitySettingSchemaAttribute[]>>();
  const getEffectiveAttributes = (entitySetting: BasicStoreEntityEntitySetting | undefined) => {
    if (!entitySetting) return Promise.resolve([]);
    let effective = effectiveBySetting.get(entitySetting.id);
    if (!effective) {
      effective = getEntitySettingSchemaAttributes(context, user, entitySetting);
      effectiveBySetting.set(entitySetting.id, effective);
    }
    return effective;
  };

  return Promise.all(types.map(async (type) => {
    const attributes = schemaAttributesDefinition.getAttributes(type);
    const attributesArray = Array.from(attributes.values());

    // The effective mandatory status and default values, as configured in Entity Settings
    // for this type: same logic as entitySettingByType, reused so the two stay consistent
    // (US.2). A type without entity settings (e.g. an internal type) keeps the raw schema
    // mandatoryType and no default values, as before this chunk.
    const entitySetting = await getEntitySettingFromCache(context, type);
    const effectiveAttributes = await getEffectiveAttributes(entitySetting);
    const effectiveByName = new Map(effectiveAttributes.map((effective) => [effective.name, effective]));

    // Map attributes to TypeAttribute format
    const typeAttributes = attributesArray
      .filter((attr) => !INTERNAL_ATTRIBUTES.includes(attr.name))
      .map((attr) => {
        const effective = effectiveByName.get(attr.name);
        return ({
          name: attr.name,
          type: attr.type,
          label: attr.label || attr.name,
          description: attr.description ?? null,
          mandatory: effective ? effective.mandatory : attr.mandatoryType === 'external',
          mandatoryType: attr.mandatoryType,
          editDefault: attr.editDefault,
          multiple: attr.multiple || false,
          upsert: attr.upsert || false,
          // For numeric attributes with scalable property
          scale: attr.type === 'numeric' && (attr as any).scalable ? 'default' : undefined,
          defaultValues: effective?.defaultValues ?? undefined,
        } as TypeAttribute);
      });

    // Add the refs (createdBy, objectMarking, objectLabel…): a type with no ref registered
    // at all (e.g. an internal type) throws instead of returning an empty list.
    let refs: RefAttribute[];
    try {
      refs = schemaRelationsRefDefinition.getRelationsRef(type);
    } catch (error) {
      const code = (error as { extensions?: { code?: string } })?.extensions?.code;
      if (code !== UNSUPPORTED_ERROR) throw error;
      refs = [];
    }
    for (const ref of refs) {
      const effective = effectiveByName.get(ref.name);
      // Enforce reference (Entity Settings) makes an external reference mandatory at creation,
      // as the schema validator does, although the ref itself is not customizable.
      const isEnforcedReference = ref.name === INPUT_EXTERNAL_REFS && entitySetting?.enforce_reference === true;
      typeAttributes.push({
        name: ref.name,
        type: 'ref',
        label: ref.label || ref.name,
        description: ref.description ?? null,
        mandatory: isEnforcedReference || (effective ? effective.mandatory : ref.mandatoryType === 'external'),
        mandatoryType: ref.mandatoryType,
        editDefault: ref.editDefault,
        multiple: ref.multiple || false,
        upsert: ref.upsert || false,
        scale: undefined,
        // The default value of objectMarking is not a marking id but a flag ('true'/'false'):
        // the creation applies the default markings of the user, so none is exposed here.
        defaultValues: ref.name === INPUT_MARKINGS ? undefined : (effective?.defaultValues ?? undefined),
      } as TypeAttribute);
    }

    // Inject custom field attributes dynamically
    const customFieldAttributes = await getDynamicTypeAttributeForEntityType(context, user, type);
    for (const cfAttribute of customFieldAttributes) {
      typeAttributes.push(cfAttribute);
    }

    return {
      type,
      attributes: typeAttributes,
    };
  }));
};
