import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin, queryAsAdminWithError, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const LIST_QUERY = gql`
  query vocabularies(
    $category: VocabularyCategory
    $first: Int
    $after: ID
    $orderBy: VocabularyOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    vocabularies(
      category: $category
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query vocabulary($id: String!) {
    vocabulary(id: $id) {
      id
      name
      description
    }
  }
`;

const CREATE_QUERY = gql`
  mutation VocabularyAdd($input: VocabularyAddInput!) {
    vocabularyAdd(input: $input) {
      id
      name
      category {
        key
        fields {
          key
        }
      }
    }
  }
`;

const UPDATE_QUERY = gql`
  mutation VocabularyFieldPatch($id: ID!, $input: [EditInput!]!) {
    vocabularyFieldPatch(id: $id, input: $input) {
      id
      name
    }
  }
`;

describe('Vocabulary resolver standard behavior', () => {
  let vocabularyInternalId;
  const vocabularyStixId = 'vocabulary--6fb9161e-bf30-11ed-afa1-0242ac120002';
  it('should vocabulary created', async () => {
    // Create the vocabulary
    const VOCABULARY_TO_CREATE = {
      input: {
        name: 'facebook',
        stix_id: vocabularyStixId,
        category: 'account_type_ov',
        description: 'Specifies a Facebook account',
      },
    };
    const vocabulary = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: VOCABULARY_TO_CREATE,
    });
    expect(vocabulary).not.toBeNull();
    expect(vocabulary.data.vocabularyAdd).not.toBeNull();
    expect(vocabulary.data.vocabularyAdd.name).toEqual('facebook');
    vocabularyInternalId = vocabulary.data.vocabularyAdd.id;
  });
  it('should vocabulary loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: vocabularyInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.vocabulary).not.toBeNull();
    expect(queryResult.data.vocabulary.id).toEqual(vocabularyInternalId);
  });
  it('should vocabulary loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: vocabularyStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.vocabulary).not.toBeNull();
    expect(queryResult.data.vocabulary.id).toEqual(vocabularyInternalId);
  });
  it('should list vocabularies', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data).not.toBeNull();
  });
  it('should update vocabulary', async () => {
    let queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: vocabularyInternalId, input: { key: 'name', value: ['facebookApp'] } },
    });
    expect(queryResult.data.vocabularyFieldPatch.name).toEqual('facebookApp');

    // Clean
    queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: vocabularyInternalId, input: { key: 'name', value: ['facebook'] } },
    });
    expect(queryResult.data.vocabularyFieldPatch.name).toEqual('facebook');
  });
});

describe('Vocabulary resolver closed category behavior', () => {
  const CATEGORIES_QUERY = gql`
    query vocabularyCategories {
      vocabularyCategories {
        key
        closed
      }
    }
  `;
  it('should expose closed categories', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: CATEGORIES_QUERY, variables: {} });
    const categories = queryResult.data.vocabularyCategories;
    expect(categories.find(({ key }) => key === 'opinion_ov').closed).toEqual(true);
    expect(categories.find(({ key }) => key === 'account_type_ov').closed).toEqual(false);
  });
  it('should not add a new value to a closed category', async () => {
    await queryAsAdminWithError({
      query: CREATE_QUERY,
      variables: { input: { name: 'not-an-opinion', category: 'opinion_ov' } },
    }, 'This vocabulary category is closed, new values cannot be added', 'FUNCTIONAL_ERROR');
    const queryResult = await queryAsAdminWithSuccess({ query: LIST_QUERY, variables: { category: 'opinion_ov', first: 50 } });
    const names = queryResult.data.vocabularies.edges.map(({ node }) => node.name);
    expect(names).not.toContain('not-an-opinion');
  });
  it('should not rename a value of a closed category', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: LIST_QUERY, variables: { category: 'opinion_ov', search: 'neutral', first: 10 } });
    const neutral = queryResult.data.vocabularies.edges.find(({ node }) => node.name === 'neutral').node;
    await queryAsAdminWithError({
      query: UPDATE_QUERY,
      variables: { id: neutral.id, input: { key: 'name', value: ['not-an-opinion'] } },
    }, 'This vocabulary category is closed, new values cannot be added', 'FUNCTIONAL_ERROR');
  });
});
