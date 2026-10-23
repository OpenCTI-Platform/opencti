import type { Resolvers, VocabularyDefinition } from '../../generated/graphql';
import { addVocabulary, deleteVocabulary, editVocabulary, findVocabularyPaginated, findById, getVocabularyUsages } from './vocabulary-domain';
import { getVocabulariesCategories, getVocabularyCategory } from './vocabulary-utils';

const vocabularyResolvers: Resolvers = {
  Query: {
    vocabulary: (_, { id }, context) => findById(context, context.user, id),
    vocabularies: (_, args, context) => findVocabularyPaginated(context, context.user, args),
    vocabularyCategories: () => getVocabulariesCategories(),
  },
  Vocabulary: {
    category: (current) => getVocabularyCategory(current.category) ?? getVocabulariesCategories().at(0) as VocabularyDefinition,
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
  },
};

export default vocabularyResolvers;
