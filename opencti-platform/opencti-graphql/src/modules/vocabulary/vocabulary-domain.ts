import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import type { EditInput, QueryVocabulariesArgs, VocabularyAddInput, VocabularyCategory } from '../../generated/graphql';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { countAllThings, type EntityOptions, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY, isVocabularyCategoryEnabled, type StoreEntityVocabulary, vocabularyDefinitions } from './vocabulary-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { elRawUpdateByQuery } from '../../database/engine';
import { READ_ENTITIES_INDICES } from '../../database/utils';
import { getVocabulariesCategories, getVocabularyCategory, openVocabularies, updateElasticVocabularyValue } from './vocabulary-utils';
import type { DomainFindById } from '../../domain/domainTypes';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { normalizeName } from '../../schema/identifier';
import { addFilter } from '../../utils/filtering/filtering-utils';

export const findById: DomainFindById<BasicStoreEntityVocabulary> = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById(context, user, id, ENTITY_TYPE_VOCABULARY);
};

export const findVocabularyPaginated = (context: AuthContext, user: AuthUser, opts: QueryVocabulariesArgs) => {
  const { category } = opts;
  let { filters } = opts;
  const entityTypes = (filters?.filters ?? []).find(({ key }) => key.includes('entity_types'));
  if (category) {
    filters = addFilter(filters, 'category', category);
  } else if (entityTypes?.values && entityTypes?.values.length > 0) {
    const categories = entityTypes.values.flatMap((type) => getVocabulariesCategories()
      .filter(({ entity_types }) => type && entity_types.includes(type))
      .map(({ key }) => key));
    const filterGroup = filters ? {
      ...filters,
      filters: (filters?.filters ?? []).filter(({ key }) => !key.includes('entity_types')),
    } : undefined;
    filters = addFilter(
      filterGroup,
      'category',
      categories,
      entityTypes.operator ?? undefined,
    );
  }
  const args = {
    orderBy: ['order', 'name'], // Default orderBy if none
    ...opts,
  };
  return pageEntitiesConnection<BasicStoreEntityVocabulary>(context, user, [ENTITY_TYPE_VOCABULARY], {
    ...args,
    filters,
  });
};

export const getVocabularyUsages = async (context: AuthContext, user: AuthUser, vocabulary: BasicStoreEntityVocabulary) => {
  const categoryDefinition = getVocabularyCategory(vocabulary.category);
  if (!categoryDefinition) {
    throw UnsupportedError(`Cant find category for vocabulary ${vocabulary.name}`);
  }
  // A hidden category's field is not registered, so no filter can count it
  if (!isVocabularyCategoryEnabled(vocabularyDefinitions[categoryDefinition.key])) {
    return 0;
  }
  // A composite field stores the vocabulary value in a sub-attribute of a nested attribute: it needs a nested filter
  // (the generated category type does not expose `composite`, the definition does)
  const { fields } = vocabularyDefinitions[vocabulary.category];
  const plainFields = fields.filter((f) => !f.composite);
  const compositeFields = fields.filter((f) => f.composite);
  const usageFilters = [
    ...(plainFields.length > 0 ? [{ key: plainFields.map((f) => f.key), values: [vocabulary.name] }] : []),
    ...compositeFields.map((f) => ({
      key: [f.key],
      operator: FilterOperator.Eq,
      mode: FilterMode.Or,
      values: [{ key: f.composite, operator: FilterOperator.Eq, values: [vocabulary.name] }],
    })),
  ];
  return countAllThings(context, user, {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['entity_type'], values: categoryDefinition.entity_types },
      ],
      filterGroups: [{ mode: FilterMode.Or, filters: usageFilters, filterGroups: [] }],
    },
  });
};

export const findAllVocabularies = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntityVocabulary> = {}) => {
  return fullEntitiesList<BasicStoreEntityVocabulary>(context, user, [ENTITY_TYPE_VOCABULARY], args);
};

// A closed category only accepts its default values, new ones can't be added
export const isVocabularyNameAllowed = (category: VocabularyCategory, name: string) => {
  if (!vocabularyDefinitions[category]?.closed) {
    return true;
  }
  const allowedNames = (openVocabularies[category] ?? []).map(({ key }) => normalizeName(key));
  return allowedNames.includes(normalizeName(name));
};

const checkVocabularyNameAllowed = (category: VocabularyCategory, name: string) => {
  if (!isVocabularyNameAllowed(category, name)) {
    throw FunctionalError('This vocabulary category is closed, new values cannot be added', { category, name });
  }
};

// is_hidden is not part of the add input of the API (an entry is hidden by editing it), but the platform stores it on creation
export const addVocabulary = async (context: AuthContext, user: AuthUser, vocabulary: VocabularyAddInput & { is_hidden?: boolean }) => {
  checkVocabularyNameAllowed(vocabulary.category, vocabulary.name);
  const element = await createEntity(context, user, { ...vocabulary, order: vocabulary.order ?? 0 }, ENTITY_TYPE_VOCABULARY);
  return notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].ADDED_TOPIC, element, user);
};

export const deleteVocabulary = async (context: AuthContext, user: AuthUser, vocabularyId: string, props?: Record<string, unknown>) => {
  const vocabulary = await findById(context, user, vocabularyId);
  const usages = await getVocabularyUsages(context, user, vocabulary);
  const completeCategory = getVocabularyCategory(vocabulary.category);
  const deletable = !vocabulary.builtIn && (!completeCategory || (!completeCategory.fields.some(({ required }) => required) || usages === 0));
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
                            query: vocabulary.name,
                          },
                        },
                      })),
                    ],
                    minimum_should_match: 1,
                  },
                },
                {
                  bool: {
                    should: [
                      ...completeCategory.fields.map((f) => ({
                        exists: {
                          field: f.key,
                        },
                      })),
                    ],
                    minimum_should_match: 1,
                  },
                },
              ],
            },
          },
        },
      });
    }
    await deleteElementById(context, user, vocabularyId, ENTITY_TYPE_VOCABULARY, props);
  }
  return vocabularyId;
};

export const editVocabulary = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[], props: Record<string, unknown>) => {
  if (input.some(({ key }) => key === 'name')) {
    const name = input.find(({ key }) => key === 'name')?.value[0];
    const oldValue = await findById(context, user, id);
    if (name) {
      checkVocabularyNameAllowed(oldValue.category, name);
      const completeCategory = getVocabularyCategory(oldValue.category);
      if (completeCategory) {
        await updateElasticVocabularyValue([oldValue.name], name, completeCategory);
      }
    }
  }
  const { element } = await updateAttribute<StoreEntityVocabulary>(context, user, id, ENTITY_TYPE_VOCABULARY, input, props);
  await notify(BUS_TOPICS[ENTITY_TYPE_VOCABULARY].EDIT_TOPIC, element, user);
  return element;
};
