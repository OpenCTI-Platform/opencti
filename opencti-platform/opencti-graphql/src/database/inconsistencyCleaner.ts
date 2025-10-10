import type { AuthContext, AuthUser } from '../types/user';
import { isBypassUser } from '../utils/access';
import { internalId } from '../schema/attribute-definition';
import {elRawSearch, elRebuildRelation, ES_MAX_PAGINATION} from './engine';
import {isNotEmptyField, READ_DATA_INDICES_WITHOUT_INFERRED} from './utils';
import { DatabaseError } from '../config/errors';

const checkForRefsDuplicates = (entityDocument: any): string[] => {
  const refsWithDuplicates: string[] = [];
  const elementData = entityDocument._source;


  return refsWithDuplicates;
}

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
};
