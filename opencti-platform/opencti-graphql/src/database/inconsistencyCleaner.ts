import type { AuthContext, AuthUser } from '../types/user';
import { isBypassUser } from '../utils/access';
import { internalId } from '../schema/attribute-definition';
import { elRawSearch, elRawUpdateByQuery, ES_MAX_PAGINATION } from './engine';
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

const getLoadByInternalIdQuery = (internal_id: string) => {
  return {
    bool: {
      filter: [{
        term: {
          [`${internalId.name}.keyword`]: internal_id
        }
      }]
    }
  };
};

const loadRawElement = async (context: AuthContext, user: AuthUser, internal_id: string): Promise<any> => {
  const query = getLoadByInternalIdQuery(internal_id);
  const rawSearchQuery = {
    index: READ_DATA_INDICES_WITHOUT_INFERRED,
    size: ES_MAX_PAGINATION,
    track_total_hits: false,
    body: { query },
  };
  const rawDocument = await elRawSearch(context, user, 'None', rawSearchQuery).catch((err: any) => {
    throw DatabaseError('Find direct ids fail', { cause: err, rawSearchQuery });
  });

  if (rawDocument.hits?.hits?.length === 0) {
    return null;
  }
  return rawDocument.hits.hits[0];
};

export enum InconsistencyOperation {
  REF_DUPLICATE_CLEAN = 'ref_duplicate_clean',
  REF_MISSING_REPAIR = 'ref_missing_repair',
}
const allOperations = [InconsistencyOperation.REF_DUPLICATE_CLEAN, InconsistencyOperation.REF_MISSING_REPAIR];
export const cleanAllEntityInconsistencies = async (context: AuthContext, user: AuthUser, internal_id: string, operationsToApply: InconsistencyOperation[] = allOperations) => {
  if (!isBypassUser(user)) {
    return;
  }
  const elementDocument = await loadRawElement(context, user, internal_id);
  if (!elementDocument) {
    return;
  }
  let source = '';
  let shouldUpdate = false;
  const params: { duplicatedKeys?: string[] } = {};
  if (operationsToApply.includes(InconsistencyOperation.REF_DUPLICATE_CLEAN)) {
    const refDuplicatesKeys = checkForRefsDuplicates(elementDocument);
    if (refDuplicatesKeys) {
      params.duplicatedKeys = refDuplicatesKeys;
      source += `
          for (String keyName : params['duplicatedKeys']) {
            ctx._source[keyName]=ctx._source[keyName].stream().distinct().sorted().collect(Collectors.toList())
          }
        `;
      shouldUpdate = true;
    }
  }

  if (shouldUpdate) {
    await elRawUpdateByQuery({
      index: READ_DATA_INDICES_WITHOUT_INFERRED,
      refresh: true,
      conflicts: 'proceed',
      body: {
        script: { source, params },
        query: getLoadByInternalIdQuery(internal_id),
      },
    });
  }
};
