import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { AdditionalEntity, FormSchemaDefinition } from './form-types';
import type { StoreEntity, BasicStoreEntity } from '../../types/store';
import type { StixRelation } from '../../types/stix-2-1-sro';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { isStixDomainObjectContainer, ENTITY_TYPE_MALWARE } from '../../schema/stixDomainObject';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { detectObservableType, refangValues } from '../../utils/observable';
import { createStixPattern } from '../../python/pythonBridge';
import { FunctionalError } from '../../config/errors';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { checkObservableSyntax } from '../../utils/syntax';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { transformSpecialFields, convertFieldType } from './form-fields-converter';
import { completeEntity } from './form-entity-builder';
import { loadFormEntity } from './form-utils';

/**
 * Input fields coming from the entity-creation mutations that must NOT be copied
 * verbatim onto the pending store entity. They are either:
 *  - references that carry OpenCTI internal ids (createdBy, objectMarking, …) which
 *    cannot be resolved as STIX refs inside this bundle,
 *  - file uploads, or
 *  - GraphQL/mutation metadata (type, update, clientMutationId, …).
 * Everything else that is a scalar (or array of scalars) is copied so we do not
 * silently lose attributes (aliases, x_mitre_id, goals, channel_types, …).
 */
const PENDING_NON_SCALAR_INPUT_FIELDS = new Set<string>([
  'createdBy', 'objectMarking', 'objectLabel', 'objectOrganization',
  'objectAssignee', 'objectParticipant', 'externalReferences', 'killChainPhases',
  'objects', 'caseTemplates', 'content_mapping', 'file', 'x_opencti_files',
  'update', 'clientMutationId', 'type',
]);

const isScalarOrScalarArray = (value: unknown): boolean => {
  if (value === undefined || value === null || value === '') return false;
  const valueType = typeof value;
  if (valueType === 'string' || valueType === 'number' || valueType === 'boolean') return true;
  if (Array.isArray(value)) {
    return value.length > 0 && value.every((item) => ['string', 'number', 'boolean'].includes(typeof item));
  }
  return false;
};

/**
 * Build partial StoreEntity objects from pending-creation payloads.
 *
 * A "pending creation" is emitted by the frontend when a draft-only user creates an
 * entity on the fly inside a Form Intake lookup field. The mutation is intercepted
 * client-side and the raw mutation variables (`input` for SDOs, or the flat variable
 * object for SCOs) are forwarded here as part of the form submission so the entity
 * can be materialised in the draft bundle.
 *
 * SDO mutations: variables = { input: { name, description, aliases, … } }
 * SCO mutations: variables are flat: { type, x_opencti_description, IPv4Addr: { value }, … }
 *
 * Scalar attributes are copied generically (see PENDING_NON_SCALAR_INPUT_FIELDS for the
 * exclusions). Reference fields (createdBy, objectMarking, objectLabel) carry OpenCTI
 * internal ids that are not guaranteed to exist in the bundle and are intentionally
 * skipped: the entity is materialised in the draft where such links can be added later.
 */
const buildPendingEntities = (
  pendingList: Array<{ entityType: string; input: Record<string, any> }>,
): StoreEntity[] => {
  return pendingList.map((pending) => {
    const entity: Record<string, any> = { entity_type: pending.entityType };
    const { input } = pending;

    // SCO flat-variable format: the observable data is nested under a type key
    // e.g. { type: 'IPv4-Addr', IPv4Addr: { value: '1.2.3.4' }, x_opencti_description: '…' }
    const isObservableInput = typeof input.type === 'string' && !('name' in input);
    if (isObservableInput) {
      if (input.x_opencti_description) entity.description = input.x_opencti_description;
      if (input.x_opencti_score !== undefined && input.x_opencti_score !== null) {
        entity.x_opencti_score = input.x_opencti_score;
      }
      // Observable value: look for the camelCase type key (e.g. 'IPv4Addr', 'DomainName')
      const obsTypeKey = Object.keys(input).find((key) => key !== 'type'
        && typeof input[key] === 'object'
        && input[key] !== null
        && 'value' in input[key]);
      if (obsTypeKey) {
        entity.value = input[obsTypeKey].value;
        // Use value as name as well so the STIX converter / standard id generation can work
        entity.name = input[obsTypeKey].value;
      }
    } else {
      // SDO/generic: copy every scalar (or scalar-array) attribute except references/meta
      for (const [key, value] of Object.entries(input)) {
        if (PENDING_NON_SCALAR_INPUT_FIELDS.has(key)) continue;
        if (isScalarOrScalarArray(value)) {
          entity[key] = value;
        }
      }
    }

    return entity as StoreEntity;
  });
};

export const buildMainStixEntities = async (
  context: AuthContext,
  user: AuthUser,
  schema: FormSchemaDefinition,
  values: Record<string, any>,
  mainEntityType: string,
  isBypass: boolean = false,
): Promise<{ mainStixEntities: any[]; mainEntityStixId: string | undefined }> => {
  const mainStixEntities = [];
  let mainEntityStixId;

  if (schema.mainEntityLookup) {
    // Existing entities selected through the lookup (skipped when the user only created
    // on-the-fly entities: values.mainEntityLookup is then undefined).
    if (isNotEmptyField(values.mainEntityLookup)) {
      const vals = Array.isArray(values.mainEntityLookup) ? values.mainEntityLookup : [values.mainEntityLookup];
      const mainEntities = await Promise.all(vals.map((id: string) => {
        return loadFormEntity(context, user, id, mainEntityType);
      }));
      for (let index = 0; index < mainEntities.length; index += 1) {
        mainStixEntities.push(convertStoreToStix_2_1(mainEntities[index]));
        mainEntityStixId = mainEntities[index].standard_id;
      }
    }

    // Handle pending (deferred) entity creations for main-entity lookup
    if (isNotEmptyField(values.mainEntityLookupPending)) {
      const pendingEntities = buildPendingEntities(values.mainEntityLookupPending);
      for (let index = 0; index < pendingEntities.length; index += 1) {
        const pendingEntity = completeEntity(pendingEntities[index].entity_type, pendingEntities[index]);
        const stixPending = convertStoreToStix_2_1(pendingEntity);
        mainStixEntities.push(stixPending);
        mainEntityStixId = pendingEntity.standard_id;
      }
    }
  } else {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
      for (let index = 0; index < values.mainEntityGroups.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        for (let i = 0; i < mainEntityFields.length; i += 1) {
          const field = mainEntityFields[i];
          const fieldValue = (field.isReadOnly && !isBypass)
            ? field.defaultValue
            : values.mainEntityGroups[index][field.name];
          const convertedValue = convertFieldType(fieldValue, field);
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          mainEntity[field.attributeMapping.attributeName] = convertedValue;
        }
        mainEntity = await transformSpecialFields(context, user, mainEntity, mainEntityFields, false);
        if (mainEntityType === ENTITY_TYPE_MALWARE && isEmptyField(mainEntity.is_family)) {
          mainEntity.is_family = true;
        }
        if (mainEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(mainEntity.context)) {
          mainEntity.context = 'form';
        }
        mainEntity = completeEntity(mainEntityType, mainEntity);
        if (isStixCyberObservable(mainEntity.entity_type)) {
          if (checkObservableSyntax(mainEntity.entity_type, mainEntity) !== true) {
            throw FunctionalError('Main entity observable is not correctly formatted', {
              type: mainEntity.entity_type,
              input: mainEntity,
              doc_code: 'INCORRECT_OBSERVABLE_FORMAT',
            });
          }
        }
        mainStixEntities.push(convertStoreToStix_2_1(mainEntity));
        mainEntityStixId = mainEntity.standard_id;
      }
    } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
      const refangedMainEntityParsed = refangValues(values.mainEntityParsed);
      for (let index = 0; index < refangedMainEntityParsed.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        if (schema.mainEntityParseFieldMapping === 'pattern' && schema.mainEntityAutoConvertToStixPattern) {
          const observableValue = refangedMainEntityParsed[index];
          const observableType = detectObservableType(observableValue);
          const pattern = await createStixPattern(context, user, observableType, observableValue);
          mainEntity[schema.mainEntityParseFieldMapping] = pattern;
          mainEntity.pattern_type = 'stix';
          mainEntity.name = observableValue;
          mainEntity.x_opencti_main_observable_type = observableType;
        } else {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          mainEntity[schema.mainEntityParseFieldMapping] = refangedMainEntityParsed[index];
        }
        if (values.mainEntityFields) {
          const additionalMainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
          for (let i = 0; i < additionalMainEntityFields.length; i += 1) {
            const field = additionalMainEntityFields[i];
            const fieldValue = (field.isReadOnly && !isBypass)
              ? field.defaultValue
              : values.mainEntityFields[field.attributeMapping.attributeName];
            if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
              const convertedValue = convertFieldType(fieldValue, field);
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-expect-error
              mainEntity[field.attributeMapping.attributeName] = convertedValue;
            }
          }
          mainEntity = await transformSpecialFields(context, user, mainEntity, additionalMainEntityFields, false);
        }
        if (mainEntityType === ENTITY_TYPE_MALWARE && isEmptyField(mainEntity.is_family)) {
          mainEntity.is_family = true;
        }
        if (mainEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(mainEntity.context)) {
          mainEntity.context = 'form';
        }
        mainEntity = completeEntity(mainEntityType, mainEntity);
        if (isStixCyberObservable(mainEntity.entity_type)) {
          if (checkObservableSyntax(mainEntity.entity_type, mainEntity) !== true) {
            throw FunctionalError('Main entity observable is not correctly formatted', {
              type: mainEntity.entity_type,
              input: mainEntity,
              doc_code: 'INCORRECT_OBSERVABLE_FORMAT',
            });
          }
        }
        mainStixEntities.push(convertStoreToStix_2_1(mainEntity));
        mainEntityStixId = mainEntity.standard_id;
      }
    } else {
      let mainEntity = { entity_type: mainEntityType } as StoreEntity;
      for (let i = 0; i < mainEntityFields.length; i += 1) {
        const field = mainEntityFields[i];
        const fieldValue = (field.isReadOnly && !isBypass)
          ? field.defaultValue
          : values[field.name];
        const convertedValue = convertFieldType(fieldValue, field);
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        mainEntity[field.attributeMapping.attributeName] = convertedValue;
      }
      mainEntity = await transformSpecialFields(context, user, mainEntity, mainEntityFields, false);
      mainEntity = completeEntity(mainEntityType, mainEntity);
      if (isStixCyberObservable(mainEntity.entity_type)) {
        if (checkObservableSyntax(mainEntity.entity_type, mainEntity) !== true) {
          throw FunctionalError('Main entity observable is not correctly formatted', {
            type: mainEntity.entity_type,
            input: mainEntity,
            doc_code: 'INCORRECT_OBSERVABLE_FORMAT',
          });
        }
      }
      mainStixEntities.push(convertStoreToStix_2_1(mainEntity));
      mainEntityStixId = mainEntity.standard_id;
    }
  }

  return { mainStixEntities, mainEntityStixId };
};

export const buildAdditionalEntities = async (
  context: AuthContext,
  user: AuthUser,
  schema: FormSchemaDefinition,
  values: Record<string, any>,
  bundle: any,
  isBypass: boolean = false,
): Promise<Record<string, string[]>> => {
  const additionalEntitiesMap: Record<string, string[]> = {};
  if (!schema.additionalEntities) return additionalEntitiesMap;

  for (let index = 0; index < schema.additionalEntities.length; index += 1) {
    const additionalEntity: AdditionalEntity = schema.additionalEntities[index];
    const additionalEntityType = additionalEntity.entityType;
    if (additionalEntity.lookup) {
      if (isNotEmptyField(values[`additional_${additionalEntity.id}_lookup`])) {
        const vals = Array.isArray(values[`additional_${additionalEntity.id}_lookup`]) ? values[`additional_${additionalEntity.id}_lookup`] : [values[`additional_${additionalEntity.id}_lookup`]];
        const additionalEntities = await Promise.all(vals.map((id: string) => {
          return loadFormEntity(context, user, id, additionalEntityType);
        }));
        for (let index2 = 0; index2 < additionalEntities.length; index2 += 1) {
          const stixAdditionalEntity = convertStoreToStix_2_1(additionalEntities[index2]);
          bundle.objects.push(stixAdditionalEntity);
          if (additionalEntitiesMap[additionalEntity.id]) {
            additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
          } else {
            additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
          }
        }
      }

      // Handle pending (deferred) entity creations inside this lookup field
      const pendingKey = `additional_${additionalEntity.id}_lookup_pending`;
      if (isNotEmptyField(values[pendingKey])) {
        const pendingEntities = buildPendingEntities(values[pendingKey]);
        for (let index2 = 0; index2 < pendingEntities.length; index2 += 1) {
          const pendingEntity = completeEntity(pendingEntities[index2].entity_type, pendingEntities[index2]);
          const stixPending = convertStoreToStix_2_1(pendingEntity);
          bundle.objects.push(stixPending);
          if (additionalEntitiesMap[additionalEntity.id]) {
            additionalEntitiesMap[additionalEntity.id].push(stixPending.id);
          } else {
            additionalEntitiesMap[additionalEntity.id] = [stixPending.id];
          }
        }
      }
    } else {
      const additionalEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
      if (additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
        if (isNotEmptyField(values[`additional_${additionalEntity.id}_groups`])) {
          for (let index2 = 0; index2 < values[`additional_${additionalEntity.id}_groups`].length; index2 += 1) {
            let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
            for (let i = 0; i < additionalEntityFields.length; i += 1) {
              const field = additionalEntityFields[i];
              const fieldValue = (field.isReadOnly && !isBypass)
                ? field.defaultValue
                : values[`additional_${additionalEntity.id}_groups`][index2][field.name];
              const convertedValue = convertFieldType(fieldValue, field);
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-expect-error
              newAdditionalEntity[field.attributeMapping.attributeName] = convertedValue;
            }
            newAdditionalEntity = await transformSpecialFields(context, user, newAdditionalEntity, additionalEntityFields, false);
            if (additionalEntityType === ENTITY_TYPE_MALWARE && isEmptyField(newAdditionalEntity.is_family)) {
              newAdditionalEntity.is_family = true;
            }
            if (additionalEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(newAdditionalEntity.context)) {
              newAdditionalEntity.context = 'form';
            }
            newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
            if (isStixCyberObservable(newAdditionalEntity.entity_type)) {
              if (checkObservableSyntax(newAdditionalEntity.entity_type, newAdditionalEntity) !== true) {
                throw FunctionalError(`Observable ${additionalEntity.label} is not correctly formatted`, {
                  type: newAdditionalEntity.entity_type,
                  input: newAdditionalEntity,
                  doc_code: 'INCORRECT_OBSERVABLE_FORMAT',
                });
              }
            }
            const stixAdditionalEntity = convertStoreToStix_2_1(newAdditionalEntity);
            bundle.objects.push(stixAdditionalEntity);
            if (additionalEntitiesMap[additionalEntity.id]) {
              additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
            } else {
              additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
            }
          }
        }
      } else if (additionalEntity.multiple && additionalEntity.fieldMode === 'parsed') {
        if (isNotEmptyField(values[`additional_${additionalEntity.id}_parsed`])) {
          const refangedAdditionalParsed = refangValues(values[`additional_${additionalEntity.id}_parsed`]);
          for (let index2 = 0; index2 < refangedAdditionalParsed.length; index2 += 1) {
            let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
            if (additionalEntity.parseFieldMapping === 'pattern' && additionalEntity.autoConvertToStixPattern) {
              const observableValue = refangedAdditionalParsed[index2];
              const observableType = detectObservableType(observableValue);
              const pattern = await createStixPattern(context, user, observableType, observableValue);
              newAdditionalEntity[additionalEntity.parseFieldMapping] = pattern;
              newAdditionalEntity.pattern_type = 'stix';
              newAdditionalEntity.name = observableValue;
              newAdditionalEntity.x_opencti_main_observable_type = observableType;
            } else {
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-expect-error
              newAdditionalEntity[additionalEntity.parseFieldMapping] = refangedAdditionalParsed[index2];
            }
            if (values[`additional_${additionalEntity.id}_fields`]) {
              for (let i = 0; i < additionalEntityFields.length; i += 1) {
                const field = additionalEntityFields[i];
                const fieldValue = (field.isReadOnly && !isBypass)
                  ? field.defaultValue
                  : values[`additional_${additionalEntity.id}_fields`][field.attributeMapping.attributeName];
                if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
                  const convertedValue = convertFieldType(fieldValue, field);
                  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                  // @ts-expect-error
                  newAdditionalEntity[field.attributeMapping.attributeName] = convertedValue;
                }
              }
              newAdditionalEntity = await transformSpecialFields(context, user, newAdditionalEntity, additionalEntityFields, false);
            }
            if (additionalEntityType === ENTITY_TYPE_MALWARE && isEmptyField(newAdditionalEntity.is_family)) {
              newAdditionalEntity.is_family = true;
            }
            if (additionalEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(newAdditionalEntity.context)) {
              newAdditionalEntity.context = 'form';
            }
            newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
            if (isStixCyberObservable(newAdditionalEntity.entity_type)) {
              if (checkObservableSyntax(newAdditionalEntity.entity_type, newAdditionalEntity) !== true) {
                throw FunctionalError(`Observable ${additionalEntity.label} is not correctly formatted`, {
                  type: newAdditionalEntity.entity_type,
                  input: newAdditionalEntity,
                  doc_code: 'INCORRECT_OBSERVABLE_FORMAT',
                });
              }
            }
            const stixAdditionalEntity = convertStoreToStix_2_1(newAdditionalEntity);
            bundle.objects.push(stixAdditionalEntity);
            if (additionalEntitiesMap[additionalEntity.id]) {
              additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
            } else {
              additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
            }
          }
        }
      } else {
        const entityData = values[`additional_${additionalEntity.id}`];
        if (entityData && typeof entityData === 'object') {
          const hasAnyFieldFilled = additionalEntityFields.some((field) => {
            const value = entityData[field.name];
            return isNotEmptyField(value);
          });
          if (additionalEntity.required || hasAnyFieldFilled) {
            let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
            for (let i = 0; i < additionalEntityFields.length; i += 1) {
              const field = additionalEntityFields[i];
              const fieldValue = (field.isReadOnly && !isBypass)
                ? field.defaultValue
                : entityData[field.name];
              if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
                const convertedValue = convertFieldType(fieldValue, field);
                // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                // @ts-expect-error
                newAdditionalEntity[field.attributeMapping.attributeName] = convertedValue;
              }
            }
            newAdditionalEntity = await transformSpecialFields(context, user, newAdditionalEntity, additionalEntityFields, false);
            if (additionalEntityType === ENTITY_TYPE_MALWARE && isEmptyField(newAdditionalEntity.is_family)) {
              newAdditionalEntity.is_family = true;
            }
            if (additionalEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(newAdditionalEntity.context)) {
              newAdditionalEntity.context = 'form';
            }
            newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
            if (isStixCyberObservable(newAdditionalEntity.entity_type)) {
              if (checkObservableSyntax(newAdditionalEntity.entity_type, newAdditionalEntity) !== true) {
                throw FunctionalError(`Observable ${additionalEntity.label} is not correctly formatted`, {
                  type: newAdditionalEntity.entity_type,
                  input: newAdditionalEntity,
                  doc_code: 'INCORRECT_OBSERVABLE_FORMAT',
                });
              }
            }
            const stixAdditionalEntity = convertStoreToStix_2_1(newAdditionalEntity);
            bundle.objects.push(stixAdditionalEntity);
            if (additionalEntitiesMap[additionalEntity.id]) {
              additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
            } else {
              additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
            }
          }
        }
      }
    }
  }

  return additionalEntitiesMap;
};

export const buildRelationships = async (
  context: AuthContext,
  user: AuthUser,
  schema: FormSchemaDefinition,
  values: Record<string, any>,
  mainStixEntities: any[],
  additionalEntitiesMap: Record<string, string[]>,
  bundle: any,
): Promise<void> => {
  if (!schema.relationships || schema.relationships.length === 0 || !values.relationships) return;

  for (let i = 0; i < schema.relationships.length; i += 1) {
    const rel = schema.relationships[i];
    const submittedRel = (values.relationships as any[])?.find((r: any) => r.id === rel.id);
    if (rel.fromEntity === 'main_entity') {
      for (let j = 0; j < mainStixEntities.length; j += 1) {
        for (let k = 0; k < (additionalEntitiesMap[rel.toEntity] ?? []).length; k += 1) {
          let relationshipData: Partial<StixRelation> = {
            id: `relationship--${uuidv4()}`,
            type: 'relationship',
            spec_version: '2.1',
            created: new Date().toISOString(),
            modified: new Date().toISOString(),
            relationship_type: rel.relationshipType,
            source_ref: mainStixEntities[j].id,
            target_ref: additionalEntitiesMap[rel.toEntity][k],
          };
          if (submittedRel?.fields && rel.fields) {
            relationshipData = await transformSpecialFields(context, user, { ...relationshipData, fields: submittedRel.fields }, rel.fields, true);
          }
          bundle.objects.push(relationshipData);
        }
      }
    } else if (rel.toEntity === 'main_entity') {
      for (let j = 0; j < mainStixEntities.length; j += 1) {
        for (let k = 0; k < (additionalEntitiesMap[rel.fromEntity] ?? []).length; k += 1) {
          let relationshipData: Partial<StixRelation> = {
            id: `relationship--${uuidv4()}`,
            type: 'relationship',
            spec_version: '2.1',
            created: new Date().toISOString(),
            modified: new Date().toISOString(),
            relationship_type: rel.relationshipType,
            source_ref: additionalEntitiesMap[rel.fromEntity][k],
            target_ref: mainStixEntities[j].id,
          };
          if (submittedRel?.fields && rel.fields) {
            relationshipData = await transformSpecialFields(context, user, { ...relationshipData, fields: submittedRel.fields }, rel.fields, true);
          }
          bundle.objects.push(relationshipData);
        }
      }
    } else {
      for (let j = 0; j < (additionalEntitiesMap[rel.fromEntity] ?? []).length; j += 1) {
        for (let k = 0; k < (additionalEntitiesMap[rel.toEntity] ?? []).length; k += 1) {
          let relationshipData: Partial<StixRelation> = {
            id: `relationship--${uuidv4()}`,
            type: 'relationship',
            spec_version: '2.1',
            created: new Date().toISOString(),
            modified: new Date().toISOString(),
            relationship_type: rel.relationshipType,
            source_ref: additionalEntitiesMap[rel.fromEntity][j],
            target_ref: additionalEntitiesMap[rel.toEntity][k],
          };
          if (submittedRel?.fields && rel.fields) {
            relationshipData = await transformSpecialFields(context, user, { ...relationshipData, fields: submittedRel.fields }, rel.fields, true);
          }
          bundle.objects.push(relationshipData);
        }
      }
    }
  }
};

export const wrapInContainerOrPush = (
  mainEntityType: string,
  mainStixEntities: any[],
  bundle: any,
  includeInContainer: boolean | undefined,
): void => {
  if (includeInContainer && isStixDomainObjectContainer(mainEntityType)) {
    for (let i = 0; i < mainStixEntities.length; i += 1) {
      const stixContainer = mainStixEntities[i] as StixContainer;
      stixContainer.object_refs = bundle.objects.map((n: BasicStoreEntity) => n.id);
      bundle.objects.push(stixContainer);
    }
  } else {
    for (let i = 0; i < mainStixEntities.length; i += 1) {
      bundle.objects.push(mainStixEntities[i]);
    }
  }
};
