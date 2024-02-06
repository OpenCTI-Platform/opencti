var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
import { addVocabulary, deleteVocabulary, editVocabulary, findAll, findById, getVocabularyUsages } from './vocabulary-domain';
import { getVocabulariesCategories } from './vocabulary-utils';
const vocabularyResolvers = {
    Query: {
        vocabulary: (_, { id }, context) => findById(context, context.user, id),
        vocabularies: (_, args, context) => findAll(context, context.user, args),
        vocabularyCategories: () => getVocabulariesCategories(),
    },
    Vocabulary: {
        category: (current) => {
            var _a;
            return (_a = getVocabulariesCategories()
                .find(({ key }) => key === current.category)) !== null && _a !== void 0 ? _a : getVocabulariesCategories().at(0);
        },
        usages: (current, _, context) => getVocabularyUsages(context, context.user, current),
    },
    Mutation: {
        vocabularyAdd: (_, { input }, context) => {
            return addVocabulary(context, context.user, input);
        },
        vocabularyFieldPatch: (_, _a, context) => {
            var { id, input } = _a, props = __rest(_a, ["id", "input"]);
            return editVocabulary(context, context.user, id, input, props);
        },
        vocabularyDelete: (_, { id }, context) => {
            return deleteVocabulary(context, context.user, id);
        },
    },
};
export default vocabularyResolvers;
