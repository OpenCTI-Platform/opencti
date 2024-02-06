var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { FilterMode } from '../../generated/graphql';
import { countAllThings, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_VOCABULARY } from './vocabulary-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { elRawUpdateByQuery } from '../../database/engine';
import { READ_ENTITIES_INDICES } from '../../database/utils';
import { getVocabulariesCategories, updateElasticVocabularyValue } from './vocabulary-utils';
import { UnsupportedError } from '../../config/errors';
import { addFilter } from '../../utils/filtering/filtering-utils';
export const findById = (context, user, id) => {
    return storeLoadById(context, user, id, ENTITY_TYPE_VOCABULARY);
};
export const findAll = (context, user, opts) => {
    var _a, _b, _c;
    const { category } = opts;
    let { filters } = opts;
    const entityTypes = ((_a = filters === null || filters === void 0 ? void 0 : filters.filters) !== null && _a !== void 0 ? _a : []).find(({ key }) => key.includes('entity_types'));
    if (category) {
        filters = addFilter(filters, 'category', category);
    }
    else if ((entityTypes === null || entityTypes === void 0 ? void 0 : entityTypes.values) && (entityTypes === null || entityTypes === void 0 ? void 0 : entityTypes.values.length) > 0) {
        const categories = entityTypes.values.flatMap((type) => getVocabulariesCategories()
            .filter(({ entity_types }) => type && entity_types.includes(type))
            .map(({ key }) => key));
        const filterGroup = filters ? Object.assign(Object.assign({}, filters), { filters: ((_b = filters === null || filters === void 0 ? void 0 : filters.filters) !== null && _b !== void 0 ? _b : []).filter(({ key }) => !key.includes('entity_types')) }) : undefined;
        filters = addFilter(filterGroup, 'category', categories, (_c = entityTypes.operator) !== null && _c !== void 0 ? _c : undefined);
    }
    const args = Object.assign({ orderBy: ['order', 'name'] }, opts);
    return listEntitiesPaginated(context, user, [ENTITY_TYPE_VOCABULARY], Object.assign(Object.assign({}, args), { filters }));
};
export const getVocabularyUsages = (context, user, vocabulary) => __awaiter(void 0, void 0, void 0, function* () {
    const categoryDefinition = getVocabulariesCategories().find(({ key }) => key === vocabulary.category);
    if (!categoryDefinition) {
        throw UnsupportedError(`Cant find category for vocabulary ${vocabulary.name}`);
    }
    return countAllThings(context, user, {
        filters: {
            mode: FilterMode.And,
            filters: [
                { key: ['entity_type'], values: categoryDefinition.entity_types },
                { key: categoryDefinition.fields.map((f) => f.key), values: [vocabulary.name] }
            ],
            filterGroups: [],
        }
    });
});
export const addVocabulary = (context, user, vocabulary) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const element = yield createEntity(context, user, Object.assign(Object.assign({}, vocabulary), { order: (_a = vocabulary.order) !== null && _a !== void 0 ? _a : 0 }), ENTITY_TYPE_VOCABULARY);
    return notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].ADDED_TOPIC, element, user);
});
export const deleteVocabulary = (context, user, vocabularyId, props) => __awaiter(void 0, void 0, void 0, function* () {
    const vocabulary = yield findById(context, user, vocabularyId);
    const usages = yield getVocabularyUsages(context, user, vocabulary);
    const completeCategory = getVocabulariesCategories().find(({ key }) => key === vocabulary.category);
    const deletable = !vocabulary.builtIn && (!completeCategory || (!completeCategory.fields.some(({ required }) => required) || usages === 0));
    if (deletable) {
        if (completeCategory) {
            yield elRawUpdateByQuery({
                index: READ_ENTITIES_INDICES,
                wait_for_completion: false,
                body: {
                    script: {
                        source: 'for(field in params.category.fields) if(ctx._source[field.key] instanceof List) ctx._source[field.key].remove(ctx._source[field.key].indexOf(params.oldName)); else ctx._source[field.key] = null;',
                        lang: 'painless',
                        params: { oldName: vocabulary.name, category: completeCategory },
                    },
                    query: {
                        bool: {
                            must: [
                                {
                                    bool: {
                                        should: [
                                            ...completeCategory.fields.map((f) => ({
                                                match: {
                                                    [`${f.key}.keyword`]: {
                                                        query: vocabulary.name
                                                    }
                                                }
                                            })),
                                        ],
                                        minimum_should_match: 1
                                    }
                                },
                                {
                                    bool: {
                                        should: [
                                            ...completeCategory.fields.map((f) => ({
                                                exists: {
                                                    field: f.key,
                                                }
                                            })),
                                        ],
                                        minimum_should_match: 1
                                    }
                                }
                            ],
                        },
                    }
                },
            });
        }
        yield deleteElementById(context, user, vocabularyId, ENTITY_TYPE_VOCABULARY, props);
    }
    return vocabularyId;
});
export const editVocabulary = (context, user, id, input, props) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    if (input.some(({ key }) => key === 'name')) {
        const name = (_b = input.find(({ key }) => key === 'name')) === null || _b === void 0 ? void 0 : _b.value[0];
        const oldValue = yield findById(context, user, id);
        if (name) {
            const completeCategory = getVocabulariesCategories().find(({ key }) => key === oldValue.category);
            if (completeCategory) {
                yield updateElasticVocabularyValue([oldValue.name], name, completeCategory);
            }
        }
    }
    const { element } = yield updateAttribute(context, user, id, ENTITY_TYPE_VOCABULARY, input, props);
    yield notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].EDIT_TOPIC, element, user);
    return element;
});
