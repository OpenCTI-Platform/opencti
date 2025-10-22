import type { AuthContext, AuthUser } from '../types/user';
import { isBypassUser } from '../utils/access';
import { internalId } from '../schema/attribute-definition';
import { elRawSearch, ES_MAX_PAGINATION } from './engine';
import { READ_DATA_INDICES_WITHOUT_INFERRED } from './utils';
import { DatabaseError } from '../config/errors';
import { REL_INDEX_PREFIX } from '../schema/general';
import { isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { isStixRefUnidirectionalRelationship } from '../schema/stixRefRelationship';

const checkForRefsDuplicates = (entityDocument: any): string[] => {
  const refsWithDuplicates: string[] = [];
  const elementData: Record<string, string | string[]> = entityDocument._source;
  const elementEntityType = elementData.entity_type;
  for (let i = 0; i < Object.entries(elementData).length; i += 1) {
    const [key, value] = Object.entries(elementData)[i];
    if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      const rel = key.substring(REL_INDEX_PREFIX.length);
      const [relType] = rel.split('.');
      if (!isSingleRelationsRef(elementEntityType as string, relType) && isStixRefUnidirectionalRelationship(relType)) {
        const valueSet = new Set(value as []);
        if (valueSet.size !== value.length) {
          refsWithDuplicates.push(key);
        }
      }
    }
  }

  return refsWithDuplicates;
};

export const verifyDenormalizedRefs = async (context: AuthContext, user: AuthUser, internal_id: string) => {
  if (!isBypassUser(user)) {
    return;
  }
  const body = {
    query: {
      bool: {
        filter: [{
          term: {
            [internalId.name]: internal_id
          }
        }]
      }
    },
  };
  const query = {
    index: READ_DATA_INDICES_WITHOUT_INFERRED,
    size: ES_MAX_PAGINATION,
    track_total_hits: false,
    body,
  };
  const rawDocument = await elRawSearch(context, user, 'None', query).catch((err: any) => {
    throw DatabaseError('Find direct ids fail', { cause: err, query });
  });

  const refDuplicatesKeys = checkForRefsDuplicates(rawDocument);

  let source = '';
  if (refDuplicatesKeys) {
    source += `
          int totalElements = 0;
          for (String fieldName : params['_source'].keySet()) {
            if (fieldName.startsWith('rel_')) {
              def fieldValue = params['_source'].get(fieldName);
              if (fieldValue != null) {
                if (fieldValue instanceof List) {
                  totalElements += ((List) fieldValue).size();
                } else {
                  totalElements++;
                }
              }
            }
          }
          return totalElements;
        `;
  }
};
