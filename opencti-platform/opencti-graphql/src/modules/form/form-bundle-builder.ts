import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { AdditionalEntity, FormSchemaDefinition } from './form-types';
import type { StoreEntity, BasicStoreEntity } from '../../types/store';
import type { StixRelation } from '../../types/stix-2-1-sro';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { isNotEmptyField } from '../../database/utils';
import { detectObservableType, refangValues } from '../../utils/observable';
import { createStixPattern } from '../../python/pythonBridge';
import { transformSpecialFields } from './form-fields-converter';
import { completeEntity } from './form-entity-builder';
import { loadFormEntity } from './form-utils';
import { buildMaterializeOptions, materializeEntityFromFields } from './form-entity-materializer';
import { materializePendingRoots, type PendingUpload, withArtifactFileNotImported, withPendingExternalReferenceFiles } from './form-pending';

const toStix = (entity: StoreEntity) => withArtifactFileNotImported(withPendingExternalReferenceFiles(convertStoreToStix_2_1(entity), entity));

type MainEntitySourceMode = 'lookup' | 'multiple' | 'parsed' | 'default';

interface MainEntitySourceContext {
  context: AuthContext;
  user: AuthUser;
  schema: FormSchemaDefinition;
  values: Record<string, any>;
  mainEntityType: string;
  isBypass: boolean;
  uploads: PendingUpload[];
}

interface MainEntitySourceResult {
  mainStixEntities: any[];
  mainEntityStixId: string | undefined;
}

type EntitySourceAdapter = (ctx: MainEntitySourceContext) => Promise<MainEntitySourceResult>;

const entitySourceAdapters: Record<MainEntitySourceMode, EntitySourceAdapter> = {
  lookup: async ({ context, user, values, mainEntityType, uploads }) => {
    const mainStixEntities: any[] = [];
    let mainEntityStixId: string | undefined;

    // Existing entities selected through the lookup (skipped when the user only created
    // on-the-fly entities: values.mainEntityLookup is then undefined).
    if (isNotEmptyField(values.mainEntityLookup)) {
      const vals = Array.isArray(values.mainEntityLookup) ? values.mainEntityLookup : [values.mainEntityLookup];
      const mainEntities = await Promise.all(vals.map((id: string) => {
        return loadFormEntity(context, user, id, mainEntityType);
      }));
      for (let index = 0; index < mainEntities.length; index += 1) {
        mainStixEntities.push(toStix(mainEntities[index]));
        mainEntityStixId = mainEntities[index].standard_id;
      }
    }

    // Handle pending (deferred) entity creations for main-entity lookup
    if (isNotEmptyField(values.mainEntityLookupPending)) {
      const pendingEntities = await materializePendingRoots(context, user, values.mainEntityLookupPending, values, uploads);
      for (let index = 0; index < pendingEntities.length; index += 1) {
        const pendingEntity = completeEntity(pendingEntities[index].entity_type, pendingEntities[index]);
        const stixPending = toStix(pendingEntity);
        mainStixEntities.push(stixPending);
        mainEntityStixId = pendingEntity.standard_id;
      }
    }

    return { mainStixEntities, mainEntityStixId };
  },
  multiple: async ({ context, user, schema, values, mainEntityType, isBypass }) => {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    const mainStixEntities: any[] = [];
    let mainEntityStixId: string | undefined;
    for (let index = 0; index < values.mainEntityGroups.length; index += 1) {
      const mainEntity = await materializeEntityFromFields(
        context,
        user,
        mainEntityType,
        mainEntityFields,
        (field) => values.mainEntityGroups[index][field.name],
        buildMaterializeOptions(isBypass, {
          errorLabel: 'Main entity observable is not correctly formatted',
        }),
      );
      mainStixEntities.push(toStix(mainEntity));
      mainEntityStixId = mainEntity.standard_id;
    }
    return { mainStixEntities, mainEntityStixId };
  },
  parsed: async ({ context, user, schema, values, mainEntityType, isBypass }) => {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    const mainStixEntities: any[] = [];
    let mainEntityStixId: string | undefined;
    const refangedMainEntityParsed = refangValues(values.mainEntityParsed);
    for (let index = 0; index < refangedMainEntityParsed.length; index += 1) {
      const seedEntity: Partial<StoreEntity> = {};
      if (schema.mainEntityParseFieldMapping === 'pattern' && schema.mainEntityAutoConvertToStixPattern) {
        const observableValue = refangedMainEntityParsed[index];
        const observableType = detectObservableType(observableValue);
        const pattern = await createStixPattern(context, user, observableType, observableValue);
        Object.assign(seedEntity, {
          [schema.mainEntityParseFieldMapping]: pattern,
          pattern_type: 'stix',
          name: observableValue,
          x_opencti_main_observable_type: observableType,
        });
      } else {
        Object.assign(seedEntity, { [String(schema.mainEntityParseFieldMapping)]: refangedMainEntityParsed[index] });
      }
      const mainEntity = await materializeEntityFromFields(
        context,
        user,
        mainEntityType,
        mainEntityFields,
        (field) => values.mainEntityFields[field.attributeMapping.attributeName],
        buildMaterializeOptions(isBypass, {
          seedEntity,
          applyFields: Boolean(values.mainEntityFields),
          skipEmptyFieldValues: true,
          errorLabel: 'Main entity observable is not correctly formatted',
        }),
      );
      mainStixEntities.push(toStix(mainEntity));
      mainEntityStixId = mainEntity.standard_id;
    }
    return { mainStixEntities, mainEntityStixId };
  },
  default: async ({ context, user, schema, values, mainEntityType, isBypass }) => {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    const mainEntity = await materializeEntityFromFields(
      context,
      user,
      mainEntityType,
      mainEntityFields,
      (field) => values[field.name],
      buildMaterializeOptions(isBypass, {
        applyTypeDefaults: false,
        errorLabel: 'Main entity observable is not correctly formatted',
      }),
    );
    return { mainStixEntities: [toStix(mainEntity)], mainEntityStixId: mainEntity.standard_id };
  },
};

const resolveMainEntitySourceMode = (schema: FormSchemaDefinition): MainEntitySourceMode => {
  if (schema.mainEntityLookup) return 'lookup';
  if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') return 'multiple';
  if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') return 'parsed';
  return 'default';
};

export const buildMainStixEntities = async (
  context: AuthContext,
  user: AuthUser,
  schema: FormSchemaDefinition,
  values: Record<string, any>,
  mainEntityType: string,
  isBypass: boolean = false,
  uploads: PendingUpload[] = [],
): Promise<MainEntitySourceResult> => {
  const mode = resolveMainEntitySourceMode(schema);
  return entitySourceAdapters[mode]({ context, user, schema, values, mainEntityType, isBypass, uploads });
};

export const buildAdditionalEntities = async (
  context: AuthContext,
  user: AuthUser,
  schema: FormSchemaDefinition,
  values: Record<string, any>,
  bundle: any,
  isBypass: boolean = false,
  uploads: PendingUpload[] = [],
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
          const stixAdditionalEntity = toStix(additionalEntities[index2]);
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
        const pendingEntities = await materializePendingRoots(context, user, values[pendingKey], values, uploads);
        for (let index2 = 0; index2 < pendingEntities.length; index2 += 1) {
          const pendingEntity = completeEntity(pendingEntities[index2].entity_type, pendingEntities[index2]);
          const stixPending = toStix(pendingEntity);
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
            const additionalEntityInstance = await materializeEntityFromFields(
              context,
              user,
              additionalEntityType,
              additionalEntityFields,
              (field) => values[`additional_${additionalEntity.id}_groups`][index2][field.name],
              buildMaterializeOptions(isBypass, {
                errorLabel: `Observable ${additionalEntity.label} is not correctly formatted`,
              }),
            );
            const stixAdditionalEntity = toStix(additionalEntityInstance);
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
            const seedEntity: Partial<StoreEntity> = {};
            if (additionalEntity.parseFieldMapping === 'pattern' && additionalEntity.autoConvertToStixPattern) {
              const observableValue = refangedAdditionalParsed[index2];
              const observableType = detectObservableType(observableValue);
              const pattern = await createStixPattern(context, user, observableType, observableValue);
              Object.assign(seedEntity, {
                [additionalEntity.parseFieldMapping]: pattern,
                pattern_type: 'stix',
                name: observableValue,
                x_opencti_main_observable_type: observableType,
              });
            } else {
              Object.assign(seedEntity, { [additionalEntity.parseFieldMapping]: refangedAdditionalParsed[index2] });
            }
            const additionalEntityInstance = await materializeEntityFromFields(
              context,
              user,
              additionalEntityType,
              additionalEntityFields,
              (field) => values[`additional_${additionalEntity.id}_fields`][field.attributeMapping.attributeName],
              buildMaterializeOptions(isBypass, {
                seedEntity,
                applyFields: Boolean(values[`additional_${additionalEntity.id}_fields`]),
                skipEmptyFieldValues: true,
                errorLabel: `Observable ${additionalEntity.label} is not correctly formatted`,
              }),
            );
            const stixAdditionalEntity = toStix(additionalEntityInstance);
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
            const additionalEntityInstance = await materializeEntityFromFields(
              context,
              user,
              additionalEntityType,
              additionalEntityFields,
              (field) => entityData[field.name],
              buildMaterializeOptions(isBypass, {
                skipEmptyFieldValues: true,
                errorLabel: `Observable ${additionalEntity.label} is not correctly formatted`,
              }),
            );
            const stixAdditionalEntity = toStix(additionalEntityInstance);
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
