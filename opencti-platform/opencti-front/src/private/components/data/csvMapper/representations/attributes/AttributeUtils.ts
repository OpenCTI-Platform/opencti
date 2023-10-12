import { Attribute, AttributeWithMetadata } from '@components/data/csvMapper/representations/attributes/Attribute';
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

// try to compute a label from the attribute schema
// Cascading attempts if the following fields exist : label, then name, then key
export const getAttributeLabel = (attribute: AttributeWithMetadata, schemaAttributes: CsvMapperRepresentationAttributesFormQuery$data['schemaAttributes']) => {
  const foundAttribute = schemaAttributes?.find((attr) => attr.name === attribute.key);
  const label = foundAttribute?.label ?? foundAttribute?.name;
  return label ?? attribute.key;
};

// based_on.representations is an array of ids
// this function gives the corresponding array of Representation objects
export const getBasedOnRepresentations = (basedOn: AttributeWithMetadata, representations: Representation[]) => {
  const values = basedOn.based_on?.representations?.map((r) => representations.find((o) => o.id === r)) ?? [];
  return values.filter((v) => v !== undefined) as Representation[];
};

// get the entity type of a given ref "from" or "to"
// (refs links to an existing representation)
export const getEntityTypeForRef = (attributes: Attribute[], representations: Representation[], keyRef: 'from' | 'to') => {
  const ref = attributes.find((attr) => attr.key === keyRef);
  let fromType: string | undefined;
  if (ref && isNotEmptyField(ref.based_on?.representations)) {
    const firstRepresentationId = ref.based_on?.representations[0];
    if (firstRepresentationId) {
      fromType = representations.find((r) => r.id === firstRepresentationId)?.target.entity_type;
    }
  }
  return fromType;
};
