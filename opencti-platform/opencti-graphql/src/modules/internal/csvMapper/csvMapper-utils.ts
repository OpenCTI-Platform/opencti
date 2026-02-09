import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntityCsvMapper, CsvMapperParsed, CsvMapperRepresentation, CsvMapperResolved } from './csvMapper-types';
import { CsvMapperRepresentationType } from './csvMapper-types';
import { isEmptyField, isNotEmptyField } from '../../../database/utils';
import { fillDefaultValues, getEntitySettingFromCache } from '../../entitySetting/entitySetting-utils';
import { FunctionalError } from '../../../config/errors';
import { schemaRelationsRefDefinition } from '../../../schema/schema-relationsRef';
import { INTERNAL_REFS } from '../../../domain/attribute-utils';
import { internalFindByIds } from '../../../database/middleware-loader';
import type { BasicStoreEntity } from '../../../types/store';
import { extractRepresentative } from '../../../database/entity-representative';
import type { MandatoryType, ObjectAttribute } from '../../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { representationLabel } from '../mapper-utils';
import { isStixRelationshipExceptRef } from '../../../schema/stixRelationship';
import { isStixObject } from '../../../schema/stixCoreObject';

export interface CsvMapperSchemaAttribute {
  name: string;
  type: string;
  mandatory: boolean;
  mandatoryType: MandatoryType;
  editDefault: boolean;
  multiple: boolean;
  defaultValues?: { id: string; name: string }[];
  label: string;
  mappings?: CsvMapperSchemaAttribute[];
}

export interface CsvMapperSchemaAttributes {
  name: string;
  attributes: CsvMapperSchemaAttribute[];
}

// TS typeguard on CsvMapperRepresentation
const isCsvMapperRepresentation = (object: any): object is CsvMapperRepresentation => {
  // this is a basic validation; TODO: json validation
  return object.id && (object.type === CsvMapperRepresentationType.Entity || object.type === CsvMapperRepresentationType.Relationship);
};

export const isCsvValidRepresentationType = (representation: CsvMapperRepresentation) => {
  if (representation.type === CsvMapperRepresentationType.Relationship) {
    if (!isStixRelationshipExceptRef(representation.target.entity_type)) {
      throw FunctionalError('Unknown relationship', { type: representation.target.entity_type });
    }
  } else if (representation.type === CsvMapperRepresentationType.Entity) {
    if (!isStixObject(representation.target.entity_type)) {
      throw FunctionalError('Unknown entity', { type: representation.target.entity_type });
    }
  } else {
    throw FunctionalError('Unknown representation type', { type: representation.type });
  }
};

export const parseCsvMapper = (mapper: any): CsvMapperParsed => {
  let representations: CsvMapperRepresentation[] = [];
  if (typeof mapper?.representations === 'string') {
    try {
      representations = JSON.parse(mapper.representations);
    } catch (error) {
      throw FunctionalError('Could not parse CSV mapper: representations is not a valid JSON', { name: mapper?.name, error });
    }
  } else {
    representations = mapper?.representations ?? [];
  }

  return {
    ...mapper,
    representations,
  };
};

export const parseCsvMapperWithDefaultValues = async (context: AuthContext, user: AuthUser, mapper: any): Promise<CsvMapperResolved> => {
  if (typeof mapper?.representations !== 'string') {
    return mapper;
  }

  const { representations: parsedRepresentations } = parseCsvMapper(mapper);
  const refAttributesIndexes: string[] = [];
  const refDefaultValues = parsedRepresentations.flatMap((representation, i) => {
    const refsDefinition = schemaRelationsRefDefinition
      .getRelationsRef(representation.target.entity_type)
      .filter((ref) => !INTERNAL_REFS.includes(ref.name));
    return representation.attributes.flatMap((attribute, j) => {
      if (
        attribute.default_values
        && attribute.key !== 'objectMarking'
        && refsDefinition.map((ref) => ref.name).includes(attribute.key)
      ) {
        refAttributesIndexes.push(`${i}-${j}`);
        return attribute.default_values;
      }
      return [];
    });
  });

  const entities = await internalFindByIds<BasicStoreEntity>(context, user, refDefaultValues) as BasicStoreEntity[];
  return {
    ...mapper,
    representations: parsedRepresentations.map((representation, i) => ({
      ...representation,
      attributes: representation.attributes.map((attribute, j) => ({
        ...attribute,
        default_values: attribute.default_values?.map((val) => {
          const refEntity = entities.find((e) => e.id === val);
          const representative = refEntity ? extractRepresentative(refEntity).main : undefined;

          return {
            id: val,
            name: refAttributesIndexes.includes(`${i}-${j}`) && representative
              ? representative
              : val,
          };
        }),
      })),
    })),
  };
};

export const validateCsvMapper = async (context: AuthContext, user: AuthUser, mapper: CsvMapperParsed) => {
  if (!Array.isArray(mapper.representations) || mapper.representations.some((rep) => !isCsvMapperRepresentation(rep))) {
    throw FunctionalError('CSV mapper representations is not an array of CsvMapperRepresentation objects', { mapper_name: mapper.name });
  }

  // consider empty csv mapper as invalid to avoid being used in the importer
  if (mapper.representations.length === 0) {
    throw FunctionalError('CSV Mapper has no representation', { mapper_name: mapper.name });
  }

  await Promise.all(Array.from(mapper.representations.entries()).map(async ([idx, representation]) => {
    // Validate target type
    isCsvValidRepresentationType(representation);

    // Validate required attributes
    const entitySetting = await getEntitySettingFromCache(context, representation.target.entity_type);
    const defaultValues = fillDefaultValues(user, {}, entitySetting);
    const attributesDefs = [
      ...schemaAttributesDefinition.getAttributes(representation.target.entity_type).values(),
    ].map((def) => ({
      name: def.name,
      mandatory: def.mandatoryType === 'external',
      multiple: def.multiple,
    }));
    const refsDefs = [
      ...schemaRelationsRefDefinition.getRelationsRef(representation.target.entity_type),
    ].map((def) => ({
      name: def.name,
      mandatory: def.mandatoryType === 'external',
      multiple: def.multiple,
    }));
    [...attributesDefs, ...refsDefs].filter((schemaAttribute) => schemaAttribute.mandatory)
      .forEach((schemaAttribute) => {
        const attribute = representation.attributes.find((a) => schemaAttribute.name === a.key);
        const isColumnEmpty = isEmptyField(attribute?.column?.column_name) && isEmptyField(attribute?.based_on?.representations);
        const isDefaultValueEmpty = isEmptyField(defaultValues[schemaAttribute.name]);
        const isAttributeDefaultValueEmpty = isEmptyField(attribute?.default_values);
        if (isColumnEmpty && isDefaultValueEmpty && isAttributeDefaultValueEmpty) {
          throw FunctionalError('Missing values for required attribute', { representation: representationLabel(idx, representation), attribute: schemaAttribute.name });
        }
      });

    // Validate representation attribute configuration
    representation.attributes.forEach((attribute) => {
      // Validate based on configuration
      if (isNotEmptyField(attribute.based_on?.representations as string[] | undefined)) {
        const schemaAttribute = [...attributesDefs, ...refsDefs].find((attr) => attr.name === attribute.key);
        // Multiple
        if (!schemaAttribute?.multiple && (attribute.based_on?.representations?.length ?? 0) > 1) {
          throw FunctionalError('Attribute can\'t be multiple', { representation: representationLabel(idx, representation), attribute: attribute.key });
        }
        // Auto reference
        if (attribute.based_on?.representations?.includes(representation.id)) {
          throw FunctionalError('Can\'t reference the representation itself', { representation: representationLabel(idx, representation), attribute: attribute.key });
        }
        // Possible cycle
        const representationRefs = mapper.representations.filter((r) => attribute.based_on?.representations?.includes(r.id));
        const attributeRepresentationRefs = representationRefs.map((rr) => rr.attributes
          .filter((rra) => isNotEmptyField(rra.based_on?.representations))
          .map((rra) => rra.based_on?.representations as string[] ?? [])
          .flat())
          .flat();
        if (attributeRepresentationRefs.includes(representation.id)) {
          throw FunctionalError('Reference cycle found', { representation: representationLabel(idx, representation) });
        }
      }
    });
  }));
};

export const getCsvMapperErrorMessage = async (context: AuthContext, user: AuthUser, csvMapper: BasicStoreEntityCsvMapper) => {
  try {
    const parsedMapper = parseCsvMapper(csvMapper); // can throw JSON parsing errors
    await validateCsvMapper(context, user, parsedMapper); // can throw model validation error
    return null; // no error
  } catch (error) {
    if (error instanceof Error) {
      return error.message;
    }
    return 'Unknown error';
  }
};

export const sanitized = (mapper: CsvMapperParsed): CsvMapperParsed => {
  return {
    ...mapper,
    representations: mapper.representations.map((r) => {
      return {
        ...r,
        attributes: r.attributes.filter((attr) => {
          return (
            isNotEmptyField(attr.based_on?.representations)
            || isNotEmptyField(attr.column?.column_name)
            || isNotEmptyField(attr.default_values)
          );
        }),
      };
    }),
  };
};

export const getHashesNames = (entityType: string) => {
  const definition = schemaAttributesDefinition.getAttributes(entityType);
  const hashesDefinition = definition.get('hashes');
  if (!hashesDefinition) {
    return [];
  }
  return (hashesDefinition as ObjectAttribute).mappings.map((mapping) => (mapping.name));
};
