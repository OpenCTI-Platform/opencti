import { Promise as BluePromise } from 'bluebird';
import { findAll as getAllCases } from '../modules/case/case-domain';
import { addVocabulary, findAll as getVocabularies } from '../modules/vocabulary/vocabulary-domain';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCaseIncident } from '../modules/case/case-incident/case-incident-domain';
import { addFeedback } from '../modules/case/feedback/feedback-domain';
import { findById } from '../domain/user';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { VocabularyCategory } from '../generated/graphql';
import { deleteElementById } from '../database/middleware';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { findByType } from '../modules/entitySetting/entitySetting-domain';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';

export const up = async (next) => {
  const context = executionContext('migration');
  const casesPromise = getAllCases(context, SYSTEM_USER);
  const vocabPromise = getVocabularies(context, SYSTEM_USER, { category: 'case_types_ov' });
  const [cases, vocab] = await Promise.all([casesPromise, vocabPromise]);
  await BluePromise.map(vocab.edges, async ({ node: { name, id } }) => {
    const vocabCases = cases.edges.filter(({ node: { case_type } }) => case_type === name).map(({ node }) => node);
    await BluePromise.map(vocabCases, async (c) => {
      const firstCreator = Array.isArray(c.creator_id) ? c.creator_id.at(0) : c.creator_id;
      const authUser = await findById(context, SYSTEM_USER, firstCreator);
      const newCase = { ...c };
      delete newCase.case_type;
      switch (name) {
        case 'incident':
          await addCaseIncident(context, authUser, newCase);
          break;
        case 'feedback':
          await addFeedback(context, authUser, newCase);
          break;
        default:
          throw new Error();
      }
    });
    await deleteElementById(context, SYSTEM_USER, id, ENTITY_TYPE_VOCABULARY);
  });
  const caseEntitySettings = await findByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE);
  if (caseEntitySettings?.id) {
    await deleteElementById(context, SYSTEM_USER, caseEntitySettings.id, ENTITY_TYPE_ENTITY_SETTING);
  }

  // NEW VOCAB
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

  next();
};

export const down = async (next) => {
  next();
};
