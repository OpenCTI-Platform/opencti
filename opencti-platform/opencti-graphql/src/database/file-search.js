/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as R from 'ramda';
import { now } from '../utils/format';
import { buildRefRelationKey } from '../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { buildPagination, cursorToOffset, INDEX_FILES, READ_DATA_INDICES_WITHOUT_INTERNAL, READ_INDEX_FILES } from './utils';
import { DatabaseError } from '../config/errors';
import { logApp } from '../config/conf';
import { buildDataRestrictions, elFindByIds, elIndex, elRawCount, elRawDeleteByQuery, elRawSearch, elRawUpdateByQuery, ES_MINIMUM_FIXED_PAGINATION } from './engine';

const buildIndexFileBody = (documentId, file, entity = null) => {
  const documentBody = {
    internal_id: documentId,
    indexed_at: now(),
    file_id: file.id,
    file_data: file.content,
    name: file.name,
    uploaded_at: file.uploaded_at,
  };
  if (entity) {
    documentBody.entity_id = entity.internal_id;
    // index entity markings & organization restrictions
    documentBody.entity_type = entity.entity_type;
    documentBody.parent_types = entity.parent_types;
    documentBody[buildRefRelationKey(RELATION_OBJECT_MARKING)] = entity[RELATION_OBJECT_MARKING] ?? [];
    documentBody[buildRefRelationKey(RELATION_GRANTED_TO)] = entity[RELATION_GRANTED_TO] ?? [];
    // index entity authorized_members & authorized_authorities => not yet
    // documentBody.authorized_members = entity.authorized_members ?? [];
    // documentBody.authorized_authorities = entity.authorized_authorities ?? [];
  }
  return documentBody;
};

export const elIndexFiles = async (context, user, files) => {
  if (!files || files.length === 0) {
    return;
  }
  const entityIds = files.filter((file) => !!file.entity_id).map((file) => file.entity_id);
  const opts = { indices: READ_DATA_INDICES_WITHOUT_INTERNAL, toMap: true };
  const entitiesMap = await elFindByIds(context, user, entityIds, opts);
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const { internal_id, file_data, file_id, entity_id } = file;
    if (internal_id && file_id && file_data) {
      const entity = entity_id ? entitiesMap[entity_id] : null;
      const fileObject = {
        id: file_id,
        content: file_data,
        name: file.name,
        uploaded_at: file.uploaded_at,
      };
      const documentBody = buildIndexFileBody(internal_id, fileObject, entity);
      try {
        await elIndex(INDEX_FILES, documentBody, { pipeline: 'attachment' });
      } catch (err) {
        // catch & log error
        logApp.error('Error on file indexing', { cause: err, file_id });
        // try to index without file content
        const documentWithoutFileData = R.dissoc('file_data', documentBody);
        await elIndex(INDEX_FILES, documentWithoutFileData).catch((e) => {
          logApp.error('Error in fallback file indexing', { message: e.message, cause: e, file_id });
        });
      }
    }
  }
};

export const elUpdateFilesWithEntityRestrictions = async (entity) => {
  if (!entity) {
    return null;
  }
  const changes = {
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: entity[RELATION_OBJECT_MARKING] ?? [],
    [buildRefRelationKey(RELATION_GRANTED_TO)]: entity[RELATION_GRANTED_TO] ?? [],
  };
  const source = 'for (change in params.changes.entrySet()) { ctx._source[change.getKey()] = change.getValue() }';
  return elRawUpdateByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source, params: { changes } },
      query: {
        term: {
          'entity_id.keyword': entity.internal_id
        }
      },
    },
  }).catch((err) => {
    throw DatabaseError('Files entity restrictions indexing fail', { cause: err, entityId: entity.internal_id });
  });
};

export const elUpdateRemovedFiles = async (entity, removed = true) => {
  if (!entity) {
    return null;
  }
  const params = { removed };
  const source = 'ctx._source["removed"] = params.removed;';
  return elRawUpdateByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source, params },
      query: {
        term: {
          'entity_id.keyword': entity.internal_id
        }
      },
    },
  }).catch((err) => {
    throw DatabaseError('Files entity removed update fail', { cause: err, entityId: entity.internal_id });
  });
};

const buildFilesSearchResult = (data, first, searchAfter, connectionFormat = true, includeContent = false) => {
  const convertedHits = data.hits.hits.map((hit) => {
    const elementData = hit._source;
    const searchOccurrences = (hit.highlight && hit.highlight['attachment.content'])
      ? hit.highlight['attachment.content'].length : 0;
    const element = {
      _index: hit._index,
      id: elementData.internal_id,
      internal_id: elementData.internal_id,
      name: elementData.name,
      indexed_at: elementData.indexed_at,
      uploaded_at: elementData.uploaded_at,
      entity_id: elementData.entity_id,
      file_id: elementData.file_id,
      searchOccurrences,
      sort: hit.sort,
    };
    if (includeContent) {
      return { ...element, content: elementData.attachment.content };
    }
    return element;
  });
  if (connectionFormat) {
    const nodeHits = R.map((n) => ({ node: n, sort: n.sort }), convertedHits);
    return buildPagination(first, searchAfter, nodeHits, data.hits.total.value);
  }
  return convertedHits;
};
const decodeSearch = (search) => {
  let decodedSearch;
  try {
    decodedSearch = decodeURIComponent(search).trim();
  } catch (_e) {
    decodedSearch = search.trim();
  }
  return decodedSearch;
};
const elBuildSearchFilesQueryBody = async (context, user, options = {}) => {
  const { search = null, fileIds = [], entityIds = [] } = options; // search options
  const { includeAuthorities = false, excludeRemoved = true } = options;
  const dataRestrictions = await buildDataRestrictions(context, user, { includeAuthorities });
  const must = [...dataRestrictions.must];
  const mustNot = [...dataRestrictions.must_not];
  if (search) {
    const decodedSearch = decodeSearch(search);
    const fullTextSearch = {
      simple_query_string: {
        query: decodedSearch,
        fields: ['attachment.content', 'attachment.title^2']
      }
    };
    must.push(fullTextSearch);
  }
  if (fileIds?.length > 0) {
    must.push({ terms: { 'file_id.keyword': fileIds } });
  }
  if (entityIds?.length > 0) {
    must.push({ terms: { 'entity_id.keyword': entityIds } });
  }
  // exclude removed files (logical deletion)
  if (excludeRemoved) {
    const excludeRemovedQuery = {
      bool: {
        should: [
          { term: { removed: { value: false } } },
          { bool: { must_not: [{ exists: { field: 'removed' } }] } }
        ]
      }
    };
    must.push(excludeRemovedQuery);
  }
  return {
    query: {
      bool: {
        must,
        must_not: mustNot,
      },
    },
  };
};
export const elSearchFiles = async (context, user, options = {}) => {
  const { search = null, first = ES_MINIMUM_FIXED_PAGINATION, after, connectionFormat = true, includeContent = false, orderBy = null, orderMode = 'asc' } = options;
  const { fields = [], excludeFields = ['attachment.content'], highlight = true } = options; // results format options
  const searchAfter = after ? cursorToOffset(after) : undefined;
  const body = await elBuildSearchFilesQueryBody(context, user, options);
  body.size = first;
  const sort = [];
  if (!orderBy) {
    // order by last indexed date by default
    if (search) {
      sort.push({ _score: 'desc' });
    }
    sort.push({ indexed_at: 'desc' });
    // add internal_id sort since indexed_at is not unique
    sort.push({ 'internal_id.keyword': 'desc' });
  } else {
    sort.push({ [orderBy]: orderMode });
  }
  body.sort = sort;
  if (searchAfter) {
    body.search_after = searchAfter;
  }
  if (highlight) {
    body.highlight = {
      fields: {
        'attachment.content': { type: 'unified', boundary_scanner: 'word', number_of_fragments: 100 }
      }
    };
  }
  const sourceIncludes = (fields?.length > 0) ? fields : [];
  const sourceExcludes = (excludeFields?.length > 0) ? excludeFields : [];
  const query = {
    index: INDEX_FILES,
    track_total_hits: true,
    _source: { includes: sourceIncludes, excludes: sourceExcludes },
    body,
  };
  logApp.debug('[SEARCH] search files', { query });
  return elRawSearch(context, user, null, query)
    .then((data) => {
      return buildFilesSearchResult(data, first, body.search_after, connectionFormat, includeContent);
    })
    .catch((err) => {
      throw DatabaseError('Files search pagination fail', { cause: err, query });
    });
};

export const elCountFiles = async (context, user, options = {}) => {
  const body = await elBuildSearchFilesQueryBody(context, user, options);
  const query = { index: INDEX_FILES, body };
  logApp.debug('elCountFiles', { query });
  return elRawCount(query);
};

export const elDeleteFilesByIds = async (fileIds) => {
  if (!fileIds) {
    return;
  }
  const query = {
    terms: { 'file_id.keyword': fileIds },
  };
  await elRawDeleteByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    body: { query },
  }).catch((err) => {
    throw DatabaseError('Error deleting files by ids', { cause: err });
  });
};

export const elDeleteAllFiles = async () => {
  await elRawDeleteByQuery({
    index: READ_INDEX_FILES,
    refresh: true,
    body: {
      query: {
        match_all: {},
      }
    },
  }).catch((err) => {
    throw DatabaseError('Error deleting all files ', { cause: err });
  });
};
