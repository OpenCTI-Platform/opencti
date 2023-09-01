import type { AuthContext } from '../../../types/user';
import type { BasicStoreEntityCsvMapper, CsvMapperRepresentation } from './csvMapper-types';
import { getSchemaAttributes } from '../../../domain/attribute';
import { isEmptyField, isNotEmptyField } from '../../../database/utils';
import { isStixRelationshipExceptRef } from '../../../schema/stixRelationship';
import { isStixObject } from '../../../schema/stixCoreObject';
import { CsvMapperRepresentationType } from './csvMapper-types';

const representationLabel = (idx: number, representation: CsvMapperRepresentation) => {
  const number = `#${idx + 1}`;
  if (isEmptyField(representation.target.entity_type)) {
    return `${number} New ${representation.type} representation`;
  }
  return `${number} ${representation.target.entity_type}`;
};

export const parseCsvMapper = (entity: any) => {
  return {
    ...entity,
    representations: typeof entity.representations === 'string' ? JSON.parse(entity.representations) : entity.representations,
  };
};

export const isValidTargetType = (representation: CsvMapperRepresentation) => {
  if (representation.type === CsvMapperRepresentationType.relationship) {
    if (!isStixRelationshipExceptRef(representation.target.entity_type)) {
      throw Error(`Unknown relationship ${representation.target.entity_type}`);
    }
  } else if (representation.type === CsvMapperRepresentationType.entity) {
    if (!isStixObject(representation.target.entity_type)) {
      throw Error(`Unknown entity ${representation.target.entity_type}`);
    }
  }
};

export const validate = async (context: AuthContext, mapper: BasicStoreEntityCsvMapper) => {
  await Promise.all(Array.from(mapper.representations.entries()).map(async ([idx, representation]) => {
    // Validate target type
    isValidTargetType(representation);

    // Validate required attributes
    const schemaAttributes = await getSchemaAttributes(context, representation.target.entity_type);
    schemaAttributes.filter((schemaAttribute) => schemaAttribute.mandatory)
      .forEach((schemaAttribute) => {
        const attribute = representation.attributes.find((a) => schemaAttribute.name === a.key);
        if (isEmptyField(attribute) || (isEmptyField(attribute?.column?.column_name) && isEmptyField(attribute?.based_on?.representations))) {
          throw Error(`Representation ${representationLabel(idx, representation)} - missing values for required attribute : ${schemaAttribute.name}`);
        }
      });

    // Validate representation attribute configuration
    representation.attributes.forEach((attribute) => {
      // Validate based on configuration
      if (isNotEmptyField(attribute.based_on?.representations)) {
        const schemaAttribute = schemaAttributes.find((attr) => attr.name === attribute.key);
        // Multiple
        if (!schemaAttribute?.multiple && (attribute.based_on?.representations?.length ?? 0) > 1) {
          throw Error(`Representation ${representationLabel(idx, representation)} - the following attribute can't be multiple : ${attribute.key}`);
        }
      }
    });
  }));
};

export const errors = async (context: AuthContext, csvMapper: BasicStoreEntityCsvMapper) => {
  try {
    await validate(context, parseCsvMapper(csvMapper));
    return null;
  } catch (error) {
    if (error instanceof Error) {
      return error.message;
    }
    return 'Unknown error';
  }
};

export const sanitized = (mapper: BasicStoreEntityCsvMapper) => {
  return {
    ...mapper,
    representations: mapper.representations.map((r) => {
      return {
        ...r,
        attributes: r.attributes.filter((attr) => {
          return isNotEmptyField(attr.based_on?.representations) || isNotEmptyField(attr.column?.column_name);
        })
      };
    })
  };
};
