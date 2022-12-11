import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, storeLoadById, updateAttribute } from '../../database/middleware';
import type {
  EditInput,
  QueryVocabulariesArgs,
  VocabularyAddInput,
  VocabularyCategory,
  VocabularyDefinition,
  VocabularyMergeInput,
} from '../../generated/graphql';
import { VocabularyFilter } from '../../generated/graphql';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import { BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY, StoreEntityVocabulary } from './vocabulary-types';
import { notify, storeMergeEvent } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { elRawSearch, elRawUpdateByQuery } from '../../database/engine';
import { READ_ENTITIES_INDICES } from '../../database/utils';
import { getVocabulariesCategories } from './vocabulary-utils';

export const findById = (context: AuthContext, user: AuthUser, id: string): BasicStoreEntityVocabulary => {
  return storeLoadById(context, user, id, ENTITY_TYPE_VOCABULARY) as unknown as BasicStoreEntityVocabulary;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryVocabulariesArgs) => {
  const { category } = opts;
  let filters = opts.filters ?? [];
  const entityTypes = filters.find(({ key }) => key.includes(VocabularyFilter.EntityTypes));
  if (category) {
    filters.push({ key: [VocabularyFilter.Category], values: [category] });
  } else if (entityTypes?.values && entityTypes?.values.length > 0) {
    const categories = entityTypes.values.flatMap((type) => getVocabulariesCategories()
      .filter(({ entity_types }) => entity_types.includes(type))
      .map(({ key }) => key));
    filters = [
      ...filters.filter(({ key }) => !key.includes(VocabularyFilter.EntityTypes)),
      {
        key: [VocabularyFilter.Category],
        values: categories,
        operator: entityTypes.operator,
      }];
  }
  return listEntitiesPaginated<BasicStoreEntityVocabulary>(context, user, [ENTITY_TYPE_VOCABULARY], {
    ...opts,
    filters
  });
};

export const getVocabularyUsages = async (context: AuthContext, user: AuthUser, vocabulary: BasicStoreEntityVocabulary) => {
  const categoryDefinition = getVocabulariesCategories().find(({ key }) => key === vocabulary.category);
  if (categoryDefinition) {
    const query = {
      index: READ_ENTITIES_INDICES,
      body: {
        query: {
          bool: {
            must: [
              {
                bool: {
                  should: [
                    ...categoryDefinition.fields.map((f) => ({
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
                    ...categoryDefinition.fields.map((f) => ({
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
    };
    const { hits } = await elRawSearch(
      context,
      user,
      ENTITY_TYPE_VOCABULARY,
      query,
    );
    return hits.hits.map((h: { _id: string }) => h._id);
  }
  return [];
};

export const addVocabulary = async (context: AuthContext, user: AuthUser, vocabulary: VocabularyAddInput) => {
  const created = await createEntity(context, user, vocabulary, ENTITY_TYPE_VOCABULARY);
  return notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].ADDED_TOPIC, created, user) as BasicStoreEntityVocabulary;
};

export const deleteVocabulary = async (context: AuthContext, user: AuthUser, vocabularyId: string, props?: Record<string, unknown>) => {
  const vocabulary = await findById(context, user, vocabularyId);
  const usages = await getVocabularyUsages(context, user, vocabulary);
  const completeCategory = getVocabulariesCategories().find(({ key }) => key === vocabulary.category);
  const deletable = !vocabulary.builtIn && (!completeCategory || (!completeCategory.fields.some(({ required }) => required) || usages.length === 0));
  if (deletable) {
    if (completeCategory) {
      await elRawUpdateByQuery({
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
    await deleteElementById(context, user, vocabularyId, ENTITY_TYPE_VOCABULARY, props);
  }
  return vocabularyId;
};

const updateElasticVocabularyValue = async (oldName: string, name: string, category: VocabularyDefinition) => {
  await elRawUpdateByQuery({
    index: READ_ENTITIES_INDICES,
    wait_for_completion: false,
    body: {
      script: {
        source: 'for(field in params.category.fields) if(ctx._source[field.key] instanceof List){ ctx._source[field.key][ctx._source[field.key].indexOf(params.oldName)] = params.name; ctx._source[field.key] = ctx._source[field.key].stream().distinct().collect(Collectors.toList()) } else ctx._source[field.key] = params.name;',
        lang: 'painless',
        params: { oldName, name, category },
      },
      query: {
        bool: {
          must: [
            {
              bool: {
                should: [
                  ...category.fields.map((f) => ({
                    match: {
                      [`${f.key}.keyword`]: {
                        query: oldName
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
                  ...category.fields.map((f) => ({
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
};

export const editVocabulary = async (context: AuthContext, user: AuthUser, id: string, category: VocabularyCategory, input: EditInput[], props: Record<string, unknown>) => {
  if (input.some(({ key }) => key === 'name')) {
    const name = input.find(({ key }) => key === 'name')?.value[0];
    const oldValue = await findById(context, user, id);
    if (name) {
      const completeCategory = getVocabulariesCategories().find(({ key }) => key === category);
      if (completeCategory) {
        await updateElasticVocabularyValue(oldValue.name, name, completeCategory);
      }
    }
    const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_VOCABULARY, input, props);
    await notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].EDIT_TOPIC, element, user);
    return element;
  }
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_VOCABULARY, input, props);
  await notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].EDIT_TOPIC, element, user);
  return element;
};

export const mergeVocabulary = async (context: AuthContext, user: AuthUser, {
  fromVocab,
  toId
}: { fromVocab: VocabularyMergeInput, toId: string }) => {
  const toVocab = await findById(context, user, toId);
  const fromCompleteVocab = { ...await findById(context, user, fromVocab.id), ...fromVocab };

  const completeCategory = getVocabulariesCategories().find(({ key }) => key === toVocab.category);
  if (completeCategory) {
    await updateElasticVocabularyValue(fromCompleteVocab.name, toVocab.name, completeCategory);
  }
  await deleteVocabulary(context, user, fromVocab.id, { publishStreamEvent: false });
  const input = [
    {
      key: 'aliases',
      value: Array.from(new Set([...(fromVocab.aliases ?? []), ...(toVocab.aliases ?? []), fromVocab.name]))
    },
    { key: 'description', value: [fromVocab.description ?? toVocab.description] },
  ];
  const element = await editVocabulary(context, user, toVocab.id, toVocab.category, input, { publishStreamEvent: false });
  await storeMergeEvent(
    context,
    user,
    toVocab as StoreEntityVocabulary,
    element,
    [fromCompleteVocab as StoreEntityVocabulary],
    { dependencyDeletions: [], updatedRelations: [] },
    {}
  );
  return element;
};
