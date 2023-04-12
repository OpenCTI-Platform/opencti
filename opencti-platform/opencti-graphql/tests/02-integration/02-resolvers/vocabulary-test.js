import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query vocabularies(
    $category: VocabularyCategory
    $first: Int
    $after: ID
    $orderBy: VocabularyOrdering
    $orderMode: OrderingMode
    $filters: [VocabularyFiltering!]
    $filterMode: FilterMode
    $search: String
  ) {
    vocabularies(
      category: $category
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
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

describe('Vocabulary resolver standard behavior', () => {
  let vocabularyInternalId;
  const vocabularyStixId = 'vocabulary--6fb9161e-bf30-11ed-afa1-0242ac120002';
  it('should vocabulary created', async () => {
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
    const UPDATE_QUERY = gql`
      mutation VocabularyFieldPatch($id: ID!, $input: [EditInput!]!) {
        vocabularyFieldPatch(id: $id, input: $input) {
          id
          name
        }
      }
    `;
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
