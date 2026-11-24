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
  it('should list vocabularies by their configured order when the ordering is null', async () => {
    const queryResult = await queryAsAdminWithSuccess({
      query: LIST_QUERY,
      variables: { category: 'opinion_ov', first: 50, orderBy: null, orderMode: null },
    });
    const names = queryResult.data.vocabularies.edges.map(({ node }) => node.name);
    expect(names).toEqual(['strongly-disagree', 'disagree', 'neutral', 'agree', 'strongly-agree']);
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

describe('Vocabulary resolver parent entry behavior (#20006)', () => {
  const CHILDREN_QUERY = gql`
    query vocabularies($category: VocabularyCategory, $filters: FilterGroup) {
      vocabularies(category: $category, filters: $filters, first: 200) {
        edges {
          node {
            id
            name
            description
            parent_name
          }
        }
      }
    }
  `;
  const PATCH_QUERY = gql`
    mutation VocabularyFieldPatch($id: ID!, $input: [EditInput!]!) {
      vocabularyFieldPatch(id: $id, input: $input) {
        id
        name
        description
        parent_name
      }
    }
  `;
  const entriesOf = async (category) => {
    const result = await queryAsAdminWithSuccess({ query: CHILDREN_QUERY, variables: { category } });
    return result.data.vocabularies.edges.map(({ node }) => node);
  };
  const hostSubcategories = ['SERVER', 'WORKSTATION', 'LAPTOP', 'VIRTUAL_MACHINE', 'HYPERVISOR'];
  it('should seed every system subcategory with its category in parent_name', async () => {
    const subcategories = await entriesOf('system_subcategory_ov');
    expect(subcategories.length).toBeGreaterThanOrEqual(80);
    hostSubcategories.forEach((name) => {
      const subcategory = subcategories.find((entry) => entry.name === name);
      expect(subcategory.parent_name).toEqual('HOST');
      expect(subcategory.description).not.toMatch(/\(category: /);
    });
  });
  it('should keep the subcategories of a renamed system category', async () => {
    const host = (await entriesOf('system_category_ov')).find(({ name }) => name === 'HOST');
    await queryAsAdminWithSuccess({ query: PATCH_QUERY, variables: { id: host.id, input: { key: 'name', value: ['HOSTS'] } } });
    let subcategories = await entriesOf('system_subcategory_ov');
    hostSubcategories.forEach((name) => {
      expect(subcategories.find((entry) => entry.name === name).parent_name).toEqual('HOSTS');
    });
    expect(subcategories.filter(({ parent_name }) => parent_name === 'HOST')).toHaveLength(0);
    // Clean: the rename back carries the link back
    await queryAsAdminWithSuccess({ query: PATCH_QUERY, variables: { id: host.id, input: { key: 'name', value: ['HOST'] } } });
    subcategories = await entriesOf('system_subcategory_ov');
    hostSubcategories.forEach((name) => {
      expect(subcategories.find((entry) => entry.name === name).parent_name).toEqual('HOST');
    });
  });
  it('should keep the category of a subcategory whose description is edited', async () => {
    const server = (await entriesOf('system_subcategory_ov')).find(({ name }) => name === 'SERVER');
    const edited = await queryAsAdminWithSuccess({
      query: PATCH_QUERY,
      variables: { id: server.id, input: { key: 'description', value: ['Any server'] } },
    });
    expect(edited.data.vocabularyFieldPatch.parent_name).toEqual('HOST');
    // Clean
    await queryAsAdminWithSuccess({ query: PATCH_QUERY, variables: { id: server.id, input: { key: 'description', value: [server.description] } } });
  });
  it('should leave the other categories alone on a rename of a category with no subcategories', async () => {
    const container = (await entriesOf('system_category_ov')).find(({ name }) => name === 'CONTAINER_WORKLOAD');
    const before = await entriesOf('system_subcategory_ov');
    await queryAsAdminWithSuccess({ query: PATCH_QUERY, variables: { id: container.id, input: { key: 'name', value: ['CONTAINERS'] } } });
    await queryAsAdminWithSuccess({ query: PATCH_QUERY, variables: { id: container.id, input: { key: 'name', value: ['CONTAINER_WORKLOAD'] } } });
    const after = await entriesOf('system_subcategory_ov');
    expect(after.map(({ name, parent_name }) => `${name}:${parent_name}`).sort()).toEqual(before.map(({ name, parent_name }) => `${name}:${parent_name}`).sort());
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
