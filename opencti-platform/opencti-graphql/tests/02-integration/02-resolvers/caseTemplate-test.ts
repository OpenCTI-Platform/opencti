import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query caseTemplates(
    $first: Int
    $after: ID
    $orderBy: CaseTemplatesOrdering
    $orderMode: OrderingMode
    $search: String
  ) {
    caseTemplates(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      search: $search
    ) {
      edges {
        node {
          id
          standard_id
          name
          description
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query caseTemplate($id: String!) {
    caseTemplate(id: $id) {
      id
      standard_id
      name
      description
      created
      modified
      tasks {
        edges {
          node {
            id
          }
        }
      }
    }
  }
`;

describe('CaseTemplate resolver standard behavior', () => {
  let caseTemplateInternalId: string;
  const caseTemplateStandardId = 'caseTemplate--f505027c-997d-4243-b67c-471f994e20d4';

  it('should caseTemplate be created', async () => {
    const CREATE_QUERY = gql`
      mutation CaseTemplateAdd($input: CaseTemplateAddInput!) {
        caseTemplateAdd(input: $input) {
          id
          name
          description
          created
        }
      }
    `;
    const CASE_TEMPLATE_TO_CREATE = {
      input: {
        name: 'Case-Template',
        description: 'Case-Template description',
        tasks: [],
      },
    };
    const caseTemplate = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CASE_TEMPLATE_TO_CREATE,
    });

    expect(caseTemplate).not.toBeNull();
    expect(caseTemplate.data?.caseTemplateAdd).not.toBeNull();
    expect(caseTemplate.data?.caseTemplateAdd.name).toEqual('Case-Template');
    caseTemplateInternalId = caseTemplate.data?.caseTemplateAdd.id;
  });

  it('should caseTemplate be loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseTemplateInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseTemplate).not.toBeNull();
    expect(queryResult.data?.caseTemplate.id).toEqual(caseTemplateInternalId);
  });

  it('should caseTemplate be loaded by standard id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseTemplateStandardId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseTemplate).not.toBeNull();
    expect(queryResult.data?.caseTemplate.id).toEqual(caseTemplateStandardId);
  });

  it('should list caseTemplates', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.caseTemplates.edges.length).toBeGreaterThan(0);
  });

  it('should update caseTemplate', async () => {
    const UPDATE_QUERY = gql`
      mutation CaseTemplateEdit($id: ID!, $input: [EditInput!]!) {
        caseTemplateFieldPatch(id: $id, input: $input) {
          id
          name
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: caseTemplateInternalId, input: [{ key: 'name', value: ['Case-Template - test'] }] },
    });
    expect(queryResult.data?.caseTemplateFieldPatch.name).toEqual('Case-Template - test');
  });

  it('should add relation in caseTemplate', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation CaseTemplateEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        caseTemplateRelationAdd(id: $id, input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: caseTemplateStandardId,
        input: {
          toId: 'task--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'template-task',
        },
      },
    });
    expect(queryResult.data?.caseTemplateRelationAdd).not.toBeNull();
  });

  it('should delete relation in caseTemplate', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CaseTemplateEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        caseTemplateRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: caseTemplateInternalId,
        toId: 'task--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'template-task',
      },
    });
    expect(queryResult.data?.caseTemplateRelationDelete).not.toBeNull();
  });

  it('should caseTemplate be deleted', async () => {
    const DELETE_QUERY = gql`
      mutation caseTemplateDelete($id: ID!) {
        caseTemplateDelete(id: $id)
      }
    `;
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: caseTemplateInternalId },
    });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseTemplateStandardId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseTemplate).toBeNull();
  });
});
