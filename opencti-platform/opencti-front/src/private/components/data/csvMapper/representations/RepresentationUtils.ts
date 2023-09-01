import { v4 as uuid } from 'uuid';
import { Representation } from '@components/data/csvMapper/representations/Representation';
import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import { CsvMapper } from '@components/data/csvMapper/CsvMapper';
import { useMapAttributes } from '@components/data/csvMapper/representations/attributes/AttributeUtils';
import {
  CsvMapperRepresentationType,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerFragment_csvMapper.graphql';
import { isEmptyField, isNotEmptyField } from '../../../../../utils/utils';

// -- INIT --

export const representationInitialization = (type: CsvMapperRepresentationType) => {
  return {
    id: uuid(),
    type,
    target: {
      entity_type: '',
    },
    attributes: [] as Attribute[],
  } as Representation;
};

// -- GETTER --

export const representationLabel = (idx: number, representation: Representation) => {
  const number = `#${idx}`;
  if (isEmptyField(representation.target.entity_type)) {
    return `${number} New ${representation.type} representation`;
  }
  return `${number} ${representation.target.entity_type}`;
};

export const getEntityRepresentations = (csvMapper: CsvMapper) => {
  return csvMapper.representations.filter((r) => r.type === 'entity');
};
export const getRelationshipRepresentations = (csvMapper: CsvMapper) => {
  return csvMapper.representations.filter((r) => r.type === 'relationship');
};

// -- MAPPER --

export const useMapRepresentations = (representations: ReadonlyArray<{
  readonly attributes: ReadonlyArray<{
    readonly based_on: {
      readonly representations: ReadonlyArray<string | null> | null;
    } | null;
    readonly column: {
      readonly column_name: string | null;
    } | null;
    readonly key: string;
  }>;
  readonly id: string;
  readonly target: {
    readonly entity_type: string;
  };
  readonly type: CsvMapperRepresentationType;
}>) => {
  return (representations ?? []).concat()
    .map((r) => ({
      ...r,
      attributes: useMapAttributes(r.attributes),
    }));
};

export const sanitized = (representations: Representation[]) => {
  return representations.filter((r) => isNotEmptyField(r.target.entity_type))
    .map((r) => {
      return {
        ...r,
        attributes: r.attributes.filter((attr) => {
          return isNotEmptyField(attr.based_on?.representations) || isNotEmptyField(attr.column?.column_name);
        }),
      };
    });
};
