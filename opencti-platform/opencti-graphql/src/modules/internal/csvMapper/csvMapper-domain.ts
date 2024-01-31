import type { AuthContext, AuthUser } from '../../../types/user';
import { internalFindByIdsMapped, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityCsvMapper, ENTITY_TYPE_CSV_MAPPER, type StoreEntityCsvMapper } from './csvMapper-types';
import type { CsvMapperAddInput, EditInput, QueryCsvMappersArgs } from '../../../generated/graphql';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../../domain/internalObject';
import { bundleProcess } from '../../../parser/csv-bundler';
import { type CsvMapperSchemaAttribute, type CsvMapperSchemaAttributes, parseCsvMapperWithDefaultValues } from './csvMapper-utils';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_ATTRIBUTES, INTERNAL_REFS } from '../../../domain/attribute-utils';
import { getEntitiesListFromCache } from '../../../database/cache';
import { type BasicStoreEntityEntitySetting, ENTITY_TYPE_ENTITY_SETTING } from '../../entitySetting/entitySetting-types';
import { SYSTEM_USER } from '../../../utils/access';
import { getAttributesConfiguration } from '../../entitySetting/entitySetting-utils';
import { isNotEmptyField } from '../../../database/utils';
import { extractRepresentative } from '../../../database/entity-representative';
import { isStixCoreRelationship } from '../../../schema/stixCoreRelationship';

// -- UTILS --

export const csvMapperTest = async (context: AuthContext, user: AuthUser, configuration: string, content: string) => {
  const limitedTestingText = content.split(/\r?\n/).slice(0, 100).join('\n'); // Get 100 lines max
  const csvMapper = await parseCsvMapperWithDefaultValues(context, user, JSON.parse(configuration));
  const bundle = await bundleProcess(context, user, Buffer.from(limitedTestingText), csvMapper);
  return {
    objects: JSON.stringify(bundle.objects, null, 2),
    nbRelationships: bundle.objects.filter((object) => object.type === 'relationship').length,
    nbEntities: bundle.objects.filter((object) => object.type !== 'relationship').length,
  };
};

// -- CRUD --

export const findById = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  const csvMapper = await storeLoadById<BasicStoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
  return parseCsvMapperWithDefaultValues(context, user, csvMapper);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryCsvMappersArgs) => {
  return listEntitiesPaginated<BasicStoreEntityCsvMapper>(context, user, [ENTITY_TYPE_CSV_MAPPER], opts);
};

export const createCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperInput: CsvMapperAddInput) => {
  return createInternalObject<StoreEntityCsvMapper>(context, user, csvMapperInput, ENTITY_TYPE_CSV_MAPPER)
    .then((entity) => parseCsvMapperWithDefaultValues(context, user, entity));
};

export const fieldPatchCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperId: string, input: EditInput[]) => {
  return editInternalObject<StoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER, input)
    .then((entity) => parseCsvMapperWithDefaultValues(context, user, entity));
};

export const deleteCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  return deleteInternalObject(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
};

// -- Schema

// Fetch the list of schemas attributes by entity type extended with
// what is saved in entity settings if any.
export const csvMapperSchemaAttributes = async (context: AuthContext, user: AuthUser) => {
  const schemaAttributes: CsvMapperSchemaAttributes[] = [];

  // Add attribute definitions
  const attributesDefinitions = schemaAttributesDefinition.attributes;
  Object.keys(attributesDefinitions).forEach((key) => {
    const attributesDef = schemaAttributesDefinition.getAttributes(key);
    const attributes: CsvMapperSchemaAttribute[] = Array.from(attributesDef.values()).flatMap((attribute) => {
      if (INTERNAL_ATTRIBUTES.includes(attribute.name)) return [];
      return [{
        name: attribute.name,
        label: attribute.label,
        type: attribute.type,
        mandatoryType: attribute.mandatoryType,
        mandatory: attribute.mandatoryType === 'external',
        editDefault: attribute.editDefault,
        multiple: attribute.multiple,
        mappings: 'mappings' in attribute
          ? attribute.mappings.map((mapping) => ({
            name: mapping.name,
            label: mapping.label,
            type: mapping.type,
            mandatoryType: mapping.mandatoryType,
            mandatory: mapping.mandatoryType === 'external',
            editDefault: mapping.editDefault,
            multiple: mapping.multiple,
          }))
          : undefined
      }];
    });
    if (isStixCoreRelationship(key)) {
      attributes.push({
        name: 'from',
        label: 'from',
        type: 'ref',
        mandatoryType: 'external',
        multiple: false,
        mandatory: true,
        editDefault: false
      });
      attributes.push({
        name: 'to',
        label: 'to',
        type: 'ref',
        mandatoryType: 'external',
        multiple: false,
        mandatory: true,
        editDefault: false
      });
    }
    schemaAttributes.push({
      name: key,
      attributes
    });
  });
  // Add refs definitions
  const refsNames = schemaRelationsRefDefinition.getAllInputNames();
  const refsDefinitions = schemaRelationsRefDefinition.relationsRef;
  Object.keys(refsDefinitions).forEach((key) => {
    const refs = schemaRelationsRefDefinition.getRelationsRef(key);
    const schemaAttribute = schemaAttributes.find((a) => a.name === key) ?? {
      name: key,
      attributes: []
    };
    schemaAttribute.attributes.push(...Array.from(refs.values()).flatMap((ref) => {
      if (INTERNAL_REFS.includes(ref.name)) return [];
      return [{
        name: ref.name,
        label: ref.label,
        type: 'ref',
        mandatoryType: ref.mandatoryType,
        mandatory: ref.mandatoryType === 'external',
        editDefault: ref.editDefault,
        multiple: ref.multiple,
      }];
    }));
  });

  // Used to resolve later default values ref with ids.
  const attributesDefaultValuesToResolve: Record<string, string[]> = {};

  // Extend schema attributes with entity settings if any
  const entitySettings = await getEntitiesListFromCache<BasicStoreEntityEntitySetting>(
    context,
    SYSTEM_USER,
    ENTITY_TYPE_ENTITY_SETTING
  );
  entitySettings.forEach((entitySetting) => {
    const schemaIndex = schemaAttributes.findIndex((s) => s.name === entitySetting.target_type);
    if (schemaIndex > -1) {
      const schemaAttribute = schemaAttributes[schemaIndex];
      getAttributesConfiguration(entitySetting)?.forEach((userDefinedAttr) => {
        const attributeIndex = schemaAttribute.attributes.findIndex((a) => a.name === userDefinedAttr.name);
        if (attributeIndex > -1) {
          const attribute = schemaAttribute.attributes[attributeIndex];
          if (attribute.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
            attribute.mandatory = userDefinedAttr.mandatory;
          }
          if (isNotEmptyField(userDefinedAttr.default_values)) {
            attribute.defaultValues = userDefinedAttr.default_values?.map((v) => ({ id: v, name: v }));
            // If the default value is a ref with an id, save it to resolve it below.
            if (attribute.name !== 'objectMarking' && refsNames.includes(attribute.name)) {
              attributesDefaultValuesToResolve[`${schemaIndex}-${attributeIndex}`] = userDefinedAttr.default_values ?? [];
            }
          }
        }
      });
    }
  });

  // Resolve default values ref ids
  const idsToResolve = Object.values(attributesDefaultValuesToResolve).flat();
  const entities = await internalFindByIdsMapped(context, user, idsToResolve);
  Object.keys(attributesDefaultValuesToResolve).forEach((indexes) => {
    const [schemaIndex, attributeIndex] = indexes.split('-').map(Number);
    const defaultValues = schemaAttributes[schemaIndex]?.attributes[attributeIndex]?.defaultValues;
    if (defaultValues) {
      schemaAttributes[schemaIndex].attributes[attributeIndex].defaultValues = defaultValues.map((val) => {
        const entity = entities[val.id];
        return {
          id: val.id,
          name: entity ? (extractRepresentative(entity).main ?? val.id) : val.id
        };
      });
    }
  });

  return schemaAttributes;
};
