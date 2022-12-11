import type { Resolvers, VocabularyDefinition } from '../../generated/graphql';
import {
  addVocabulary,
  deleteVocabulary,
  editVocabulary,
  findAll,
  findById,
  getVocabularyUsages,
  mergeVocabulary
} from './vocabulary-domain';
import { getVocabulariesCategories } from './vocabulary-utils';

const vocabularyResolvers: Resolvers = {
  Query: {
    vocabulary: (_, { id }, context) => findById(context, context.user, id),
    vocabularies: (_, args, context) => findAll(context, context.user, args),
    vocabularyCategories: () => getVocabulariesCategories(),
  },
  Vocabulary: {
    category: (current) => getVocabulariesCategories()
      .find(({ key }) => key === current.category) ?? getVocabulariesCategories().at(0) as VocabularyDefinition,
    usages: (current, _, context) => getVocabularyUsages(context, context.user, current),
  },
  Mutation: {
    vocabularyAdd: (_, { input }, context) => {
      return addVocabulary(context, context.user, input);
    },
    vocabularyFieldPatch: (_, { id, input, ...props }, context) => {
      return editVocabulary(context, context.user, id, input, props);
    },
    vocabularyDelete: (_, { id }, context) => {
      return deleteVocabulary(context, context.user, id);
    },
    vocabularyMerge: (_, { fromVocab, toId }, context) => {
      return mergeVocabulary(context, context.user, { fromVocab, toId });
    },
  },
};

export default vocabularyResolvers;
