import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { FormSchemaDefinition, StoreEntityForm } from './form-types';
import type { StoreEntity, BasicStoreEntity } from '../../types/store';
import type { StixRelation } from '../../types/stix-2-1-sro';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import { storeLoadById } from '../../database/middleware-loader';
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

export const buildMainStixEntities = async (
  context: AuthContext,
  user: AuthUser,
  schema: FormSchemaDefinition,
  values: Record<string, any>,
  mainEntityType: string,
): Promise<{ mainStixEntities: any[]; mainEntityStixId: string | undefined }> => {
  const mainStixEntities = [];
  let mainEntityStixId;

  if (schema.mainEntityLookup) {
    const vals = Array.isArray(values.mainEntityLookup) ? values.mainEntityLookup : [values.mainEntityLookup];
    const mainEntities = await Promise.all(vals.map((id: string) => {
      return storeLoadById<StoreEntityForm>(context, user, id, mainEntityType);
    }));
    for (let index = 0; index < mainEntities.length; index += 1) {
      mainStixEntities.push(convertStoreToStix_2_1(mainEntities[index]));
      mainEntityStixId = mainEntities[index].standard_id;
    }
  } else {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
      for (let index = 0; index < values.mainEntityGroups.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        for (let i = 0; i < mainEntityFields.length; i += 1) {
          const field = mainEntityFields[i];
          const fieldValue = values.mainEntityGroups[index][field.name];
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
            const fieldValue = values.mainEntityFields[field.attributeMapping.attributeName];
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
        const fieldValue = values[field.name];
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
): Promise<Record<string, string[]>> => {
  const additionalEntitiesMap: Record<string, string[]> = {};
  if (!schema.additionalEntities) return additionalEntitiesMap;

  for (let index = 0; index < schema.additionalEntities.length; index += 1) {
    const additionalEntity = schema.additionalEntities[index];
    const additionalEntityType = additionalEntity.entityType;
    if (additionalEntity.lookup) {
      if (isNotEmptyField(values[`additional_${additionalEntity.id}_lookup`])) {
        const vals = Array.isArray(values[`additional_${additionalEntity.id}_lookup`]) ? values[`additional_${additionalEntity.id}_lookup`] : [values[`additional_${additionalEntity.id}_lookup`]];
        const additionalEntities = await Promise.all(vals.map((id: string) => {
          return storeLoadById<StoreEntityForm>(context, user, id, additionalEntityType);
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
    } else {
      const additionalEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
      if (additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
        if (isNotEmptyField(values[`additional_${additionalEntity.id}_groups`])) {
          for (let index2 = 0; index2 < values[`additional_${additionalEntity.id}_groups`].length; index2 += 1) {
            let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
            for (let i = 0; i < additionalEntityFields.length; i += 1) {
              const field = additionalEntityFields[i];
              const fieldValue = values[`additional_${additionalEntity.id}_groups`][index2][field.name];
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
                const fieldValue = values[`additional_${additionalEntity.id}_fields`][field.attributeMapping.attributeName];
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
              const fieldValue = entityData[field.name];
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
