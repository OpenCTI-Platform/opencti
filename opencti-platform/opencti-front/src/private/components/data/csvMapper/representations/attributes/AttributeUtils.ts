import { Attribute } from '@components/data/csvMapper/representations/attributes/Attribute';
import { Representation } from '@components/data/csvMapper/representations/Representation';
import {
  CsvMapperRepresentationAttributesFormQuery$data,
} from '@components/data/csvMapper/representations/attributes/__generated__/CsvMapperRepresentationAttributesFormQuery.graphql';
import { isNotEmptyField } from '../../../../../../utils/utils';

export const alphabet = (size = 0) => {
  const fn = () => Array.from(Array(26)).map((_, i) => i + 65)
    .map((x) => String.fromCharCode(x));
  const letters: string[] = fn();
  for (let step = 0; step < size; step += 1) {
    const additionalLetters = fn();
    const firstLetter = additionalLetters[step];
    letters.push(...additionalLetters.map((l) => firstLetter.concat(l)));
  }
  return letters;
};

// -- MAPPER --

export const useMapAttributes = (attributes: ReadonlyArray<{
  readonly based_on: {
    readonly representations: ReadonlyArray<string | null> | null;
  } | null;
  readonly column: {
    readonly column_name: string | null;
  } | null;
  readonly key: string;
}>) => {
  return (attributes ?? []).concat();
};

export const convertFromSchemaAttribute = (schemaAttribute: {
  readonly label: string | null,
  readonly mandatory: boolean,
  readonly multiple: boolean | null,
  readonly name: string
  readonly type: string
}) => {
  return ({
    key: schemaAttribute.name,
    mandatory: schemaAttribute.mandatory,
    multiple: schemaAttribute.multiple,
    type: schemaAttribute.type,
    column: {
      column_name: null,
    },
    based_on: {
      representations: null,
    },
  });
};

// -- GETTER --

export const attributeLabel = (attribute: Attribute, schemaAttributes: CsvMapperRepresentationAttributesFormQuery$data['schemaAttributes']) => {
  const foundAttribute = schemaAttributes?.find((attr) => attr.name === attribute.key);
  const label = foundAttribute?.label ?? foundAttribute?.name;
  return label ?? attribute.key;
};

export const basedOnValue = (basedOn: Attribute, representations: Representation[]) => {
  const values = basedOn.based_on?.representations?.map((r) => representations.find((o) => o.id === r)) ?? [];
  return values.filter((v) => v !== undefined) as Representation[];
};

export const entityTypeAttributeFrom = (attributes: Attribute[], representations: Representation[]) => {
  const from = attributes.find((attr) => attr.key === 'from');
  let fromType: string | undefined;
  if (from && isNotEmptyField(from.based_on?.representations)) {
    const firstRepresentation = from.based_on?.representations[0];
    if (firstRepresentation) {
      fromType = representations.find((r) => r.id === firstRepresentation)?.target.entity_type;
    }
  }
  return fromType;
};

export const entityTypeAttributeTo = (attributes: Attribute[], representations: Representation[]) => {
  const to = attributes.find((attr) => attr.key === 'to');
  let toType: string | undefined;
  if (to && isNotEmptyField(to.based_on?.representations)) {
    const firstRepresentation = to.based_on?.representations[0];
    if (firstRepresentation) {
      toType = representations.find((r) => r.id === firstRepresentation)?.target.entity_type;
    }
  }
  return toType;
};
