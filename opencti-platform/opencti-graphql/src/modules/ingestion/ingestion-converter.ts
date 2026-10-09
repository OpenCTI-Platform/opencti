import { v4 as uuid } from 'uuid';
import type { CsvMapperRepresentationResolved, CsvMapperResolved } from '../internal/csvMapper/csvMapper-types';

export const regenerateCsvMapperUUID = (csvMapper: CsvMapperResolved): CsvMapperResolved => {
  const uuidMap: Record<string, string> = {};
  csvMapper.representations.forEach((representation) => {
    const oldId = representation.id;
    uuidMap[oldId] = uuid();
  });
  return {
    ...csvMapper,
    id: uuid(),
    representations: csvMapper.representations.map((representation) => {
      let attributes = {};
      if (representation.attributes) {
        attributes = representation.attributes.map((attribute) => {
          if (attribute?.based_on?.representations) {
            return {
              ...attribute,
              based_on: {
                ...attribute.based_on,
                representations: attribute.based_on.representations.map(
                  (oldId) => uuidMap[oldId] || oldId,
                ),
              },
            };
          }
          return attribute;
        });
      }

      return {
        ...representation,
        id: uuidMap[representation.id],
        attributes,
      } as CsvMapperRepresentationResolved;
    }),
  };
};
