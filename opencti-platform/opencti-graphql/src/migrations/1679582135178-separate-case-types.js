import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { VocabularyCategory } from '../generated/graphql';
import { deleteElementById } from '../database/middleware';
import { findByType } from '../modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { listAllEntities } from '../database/middleware-loader';
import { generateStandardId } from '../schema/identifier';
import { logApp } from '../config/conf';

const message = '[MIGRATION] Cases to incident and Feedback';

const updateCaseEntity = async (fromCase, toType, standardId) => {
  const updateEntityQuery = {
    script: {
      params: { toType, standardId, original: 'Case' },
      source: 'ctx._source.entity_type = params.toType; '
          + 'ctx._source.standard_id = params.standardId; '
          + 'if (!ctx._source.parent_types.contains(params.original)) { ctx._source.parent_types.add(params.original); }',
    },
    query: {
      term: { 'internal_id.keyword': { value: fromCase.internal_id } }
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateEntityQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const updateCaseRelationships = async (fromCase, toType) => {
  const updateRelationsQuery = {
    script: {
      params: { toType, toId: fromCase.internal_id },
      source: 'for(def connection : ctx._source.connections) {'
          + ' if (connection.internal_id == params.toId && !connection.types.contains(params.toType)) { connection.types.add(params.toType); }'
          + ' if (connection.internal_id == params.toId && connection.role.endsWith("_from")) { ctx._source.fromType = params.toType; }'
          + ' if (connection.internal_id == params.toId && connection.role.endsWith("_to")) { ctx._source.toType = params.toType; }'
          + '}'
    },
    query: {
      nested: {
        path: 'connections',
        query: {
          term: { 'connections.internal_id.keyword': { value: fromCase.internal_id } }
        }
      }
    },
  };
  return elRawUpdateByQuery({
    index: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    refresh: true,
    wait_for_completion: true,
    body: updateRelationsQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // region Split cases to 'Feedback' and 'Case-Incident'
  const cases = await listAllEntities(context, SYSTEM_USER, ['Case']);
  logApp.info(`${message} > Migrating cases 0/${cases.length}`);
  let processNumber = 0;
  for (let index = 0; index < cases.length; index += 1) {
    processNumber += 1;
    const currentCase = cases[index];
    const toType = currentCase.case_type === 'feedback' ? 'Feedback' : 'Case-Incident';
    const standardId = generateStandardId(toType, currentCase);
    const updateCasePromise = updateCaseEntity(currentCase, toType, standardId);
    const updateRelationshipsPromise = updateCaseRelationships(currentCase, toType);
    await Promise.all([updateCasePromise, updateRelationshipsPromise]);
    logApp.info(`${message} > Migrating cases ${processNumber}/${cases.length}`);
  }
  // endregion

  // region Delete the classic container case setting
  const caseEntitySettings = findByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE);
  if (caseEntitySettings?.id) {
    await deleteElementById(context, SYSTEM_USER, caseEntitySettings.id, ENTITY_TYPE_ENTITY_SETTING);
  }
  // endregion

  // region Create new vocabularies
  const category = VocabularyCategory.IncidentResponseTypesOv;
  const vocabularies = openVocabularies[category] ?? [];
  for (let i = 0; i < vocabularies.length; i += 1) {
    const { key, description, aliases } = vocabularies[i];
    await addVocabulary(context, SYSTEM_USER, {
      name: key,
      description: description ?? '',
      aliases: aliases ?? [],
      category,
      builtIn: false
    });
  }
  // endregion
  // Done with the migration
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
