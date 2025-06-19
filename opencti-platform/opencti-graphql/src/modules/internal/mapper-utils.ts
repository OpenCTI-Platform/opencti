import { idsValuesRemap } from '../../database/stix-2-1-converter';
import type { AuthContext, AuthUser } from '../../types/user';
import { type CsvMapperRepresentation } from './csvMapper/csvMapper-types';
import type { JsonMapperRepresentation } from './jsonMapper/jsonMapper-types';
import { internalFindByIds } from '../../database/middleware-loader';
import type { BasicStoreObject } from '../../types/store';
import { isEmptyField } from '../../database/utils';

// csv mapper representatives converter for default values ids
// Export => ids must be converted to standard id
// Import => ids must be converted back to internal id
export const convertRepresentationsIds = async (context: AuthContext, user: AuthUser, representations: CsvMapperRepresentation[] | JsonMapperRepresentation[], from: 'internal' | 'stix') => {
  // First iteration to resolve all ids to translate
  const resolvingIds: string[] = [];
  representations.forEach((representation) => {
    representation.attributes.forEach((attribute) => {
      const defaultValues = attribute.default_values;
      if (defaultValues) {
        defaultValues.forEach((value) => resolvingIds.push(value));
      }
    });
  });
  // Resolve then second iteration to replace the ids
  const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
  const resolvedMap = await internalFindByIds(context, user, resolvingIds, resolveOpts);
  const idsMap = resolvedMap as unknown as { [k: string]: BasicStoreObject };
  representations.forEach((representation) => {
    representation.attributes.forEach((attribute) => {
      if (attribute && attribute.default_values) {
        // eslint-disable-next-line no-param-reassign
        attribute.default_values = idsValuesRemap(attribute.default_values, idsMap, from, true);
      }
    });
  });
};

export const representationLabel = (idx: number, representation: CsvMapperRepresentation | JsonMapperRepresentation) => {
  const number = `#${idx + 1}`;
  if (isEmptyField(representation.target.entity_type)) {
    return `${number} New ${representation.type} representation`;
  }
  return `${number} ${representation.target.entity_type}`;
};
