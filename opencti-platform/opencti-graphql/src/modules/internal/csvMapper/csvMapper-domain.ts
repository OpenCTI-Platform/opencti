import type { AuthContext, AuthUser } from '../../../types/user';
import { internalFindByIdsMapped, listAllEntities, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityCsvMapper, ENTITY_TYPE_CSV_MAPPER, type StoreEntityCsvMapper } from './csvMapper-types';
import { type CsvMapperAddInput, type EditInput, FilterMode, type QueryCsvMappersArgs } from '../../../generated/graphql';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../../domain/internalObject';
import { bundleProcess } from '../../../parser/csv-bundler';
import { type CsvMapperSchemaAttribute, type CsvMapperSchemaAttributes, parseCsvMapper, parseCsvMapperWithDefaultValues, validateCsvMapper } from './csvMapper-utils';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_ATTRIBUTES, INTERNAL_REFS } from '../../../domain/attribute-utils';
import { getAttributesConfiguration, getEntitySettingFromCache } from '../../entitySetting/entitySetting-utils';
import { isNotEmptyField } from '../../../database/utils';
import { extractRepresentative } from '../../../database/entity-representative';
import { isStixCoreRelationship } from '../../../schema/stixCoreRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from '../../../schema/stixSightingRelationship';
import { schemaTypesDefinition } from '../../../schema/schema-types';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_META_OBJECT } from '../../../schema/general';
import { type BasicStoreEntityIngestionCsv, ENTITY_TYPE_INGESTION_CSV } from '../../ingestion/ingestion-types';
import { FunctionalError } from '../../../config/errors';

// -- UTILS --

export const csvMapperTest = async (context: AuthContext, user: AuthUser, configuration: string, content: string) => {
  let parsedConfiguration;
  try {
    parsedConfiguration = JSON.parse(configuration);
  } catch (error) {
    throw FunctionalError('Could not parse CSV mapper configuration', { error });
  }
  const csvMapper = parseCsvMapper(parsedConfiguration);
  const bundle = await bundleProcess(context, user, Buffer.from(content), csvMapper, { maxRecordNumber: 100 });
  return {
    objects: JSON.stringify(bundle.objects, null, 2),
    nbRelationships: bundle.objects.filter((object) => object.type === 'relationship').length,
    nbEntities: bundle.objects.filter((object) => object.type !== 'relationship').length,
  };
};

// -- CRUD --

export const findById = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  return storeLoadById<BasicStoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryCsvMappersArgs) => {
  return listEntitiesPaginated<BasicStoreEntityCsvMapper>(context, user, [ENTITY_TYPE_CSV_MAPPER], opts);
};

export const createCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperInput: CsvMapperAddInput) => {
  // attempt to parse and validate the mapper representations ; this can throw errors
  const parsedMapper = parseCsvMapper(csvMapperInput);
  await validateCsvMapper(context, user, parsedMapper);

  return createInternalObject<StoreEntityCsvMapper>(context, user, csvMapperInput, ENTITY_TYPE_CSV_MAPPER);
};

export const fieldPatchCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperId: string, input: EditInput[]) => {
  return editInternalObject<StoreEntityCsvMapper>(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER, input);
};

export const deleteCsvMapper = async (context: AuthContext, user: AuthUser, csvMapperId: string) => {
  // detect if ingesters are using this mapper
  const opts = {
    filters: {
      mode: FilterMode.Or,
      filterGroups: [],
      filters: [{ key: ['csv_mapper_id'], values: [csvMapperId] }]
    }
  };
  const ingesters = await listAllEntities<BasicStoreEntityIngestionCsv>(context, user, [ENTITY_TYPE_INGESTION_CSV], opts);
  // prevent deletion if an ingester uses the mapper
  if (ingesters.length > 0) {
    throw FunctionalError('Cannot delete this CSV Mapper: it is used by one or more IngestionCsv ingester(s)', { id: csvMapperId });
  }

  return deleteInternalObject(context, user, csvMapperId, ENTITY_TYPE_CSV_MAPPER);
};

export const getParsedRepresentations = async (context: AuthContext, user: AuthUser, csvMapper: BasicStoreEntityCsvMapper) => {
  const parsedMapper = await parseCsvMapperWithDefaultValues(context, user, csvMapper);
  return parsedMapper.representations;
};

// -- Schema

// Fetch the list of schemas attributes by entity type extended with
// what is saved in entity settings if any.
export const csvMapperSchemaAttributes = async (context: AuthContext, user: AuthUser) => {
  const schemaAttributes: CsvMapperSchemaAttributes[] = [];

  const types = [
    ...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE),
    ...schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT),
    ...schemaTypesDefinition.get(ABSTRACT_STIX_META_OBJECT),
    ...schemaTypesDefinition.get(ABSTRACT_STIX_CORE_RELATIONSHIP),
    STIX_SIGHTING_RELATIONSHIP
  ].sort();

  // Add attribute definitions
  types.forEach((type) => {
    const attributesDef = schemaAttributesDefinition.getAttributes(type);
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
    if (isStixCoreRelationship(type) || isStixSightingRelationship(type)) {
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
      name: type,
      attributes
    });
  });
  // Add refs definitions
  const refsNames = schemaRelationsRefDefinition.getAllInputNames();
  types.forEach((type) => {
    const refs = schemaRelationsRefDefinition.getRelationsRef(type);
    const schemaAttribute = schemaAttributes.find((a) => a.name === type) ?? {
      name: type,
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
  for (let schemaIndex = 0; schemaIndex < schemaAttributes.length; schemaIndex += 1) {
    const schemaAttribute = schemaAttributes[schemaIndex];
    const entitySetting = await getEntitySettingFromCache(context, schemaAttribute.name);
    if (entitySetting) {
      getAttributesConfiguration(entitySetting)?.forEach((userDefinedAttr) => {
        const attributeIndex = schemaAttribute.attributes.findIndex((a) => a.name === userDefinedAttr.name);
        if (attributeIndex > -1) {
          const attribute = schemaAttribute.attributes[attributeIndex];
          if (attribute.mandatoryType === 'customizable' && isNotEmptyField(userDefinedAttr.mandatory)) {
            attribute.mandatory = userDefinedAttr.mandatory;
          }
          if (isNotEmptyField(userDefinedAttr.default_values)) {
            attribute.defaultValues = (userDefinedAttr.default_values as string[])?.map((v) => ({ id: v, name: v }));
            // If the default value is a ref with an id, save it to resolve it below.
            if (attribute.name !== 'objectMarking' && refsNames.includes(attribute.name)) {
              attributesDefaultValuesToResolve[`${schemaIndex}-${attributeIndex}`] = userDefinedAttr.default_values ?? [];
            }
          }
        }
      });
    }
  }

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
