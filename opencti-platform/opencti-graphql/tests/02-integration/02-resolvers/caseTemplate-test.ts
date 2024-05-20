import { expect, it, describe } from 'vitest';
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
  let taskTemplateInternalId: string;
  const caseTemplateStandardId = 'case-template--1a80c59c-d839-4984-af04-04f3286d8f89';

  it('should caseTemplate created', async () => {
    const CREATE_QUERY = gql`
      mutation CaseTemplateAdd($input: CaseTemplateAddInput!) {
        caseTemplateAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    const CASE_TEMPLATE_TO_CREATE = {
      input: {
        name: 'TestCaseTemplate',
        description: 'Test case template description',
        tasks: []
      },
    };
    const caseTemplate = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: CASE_TEMPLATE_TO_CREATE,
    });
    expect(caseTemplate.data?.caseTemplateAdd).not.toBeNull();
    expect(caseTemplate.data?.caseTemplateAdd.name).toEqual('TestCaseTemplate');
    caseTemplateInternalId = caseTemplate.data?.caseTemplateAdd.id;
  });

  it('should taskTemplate created', async () => {
    const CREATE_TASK_QUERY = gql`
      mutation TaskTemplateAdd($input: TaskTemplateAddInput!) {
        taskTemplateAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    const TASK_TEMPLATE_TO_CREATE = {
      input: {
        name: 'TestTaskTemplate',
        description: 'Test task template description'
      },
    };
    const taskTemplate = await queryAsAdmin({
      query: CREATE_TASK_QUERY,
      variables: TASK_TEMPLATE_TO_CREATE,
    });
    expect(taskTemplate).not.toBeNull();
    expect(taskTemplate.data?.taskTemplateAdd).not.toBeNull();
    expect(taskTemplate.data?.taskTemplateAdd.name).toEqual('TestTaskTemplate');
    taskTemplateInternalId = taskTemplate.data?.taskTemplateAdd.id;
  });

  it('should caseTemplate loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseTemplateInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseTemplate).not.toBeNull();
    expect(queryResult.data?.caseTemplate.id).toEqual(caseTemplateInternalId);
  });

  it('should list caseTemplates', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.caseTemplates.edges.length).toBeGreaterThan(0);
  });

  it('should update caseTemplate', async () => {
    const UPDATE_QUERY = gql`
      mutation CaseTemplateFieldPatch($id: ID!, $input: [EditInput!]!) {
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
      mutation CaseTemplateRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
        caseTemplateRelationAdd(id: $id, input: $input) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: caseTemplateInternalId,
        input: {
          toId: taskTemplateInternalId,
          relationship_type: 'template-task',
        },
      },
    });
    expect(queryResult.data?.caseTemplateRelationAdd).not.toBeNull();
    const readQueryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: caseTemplateInternalId } });
    expect(readQueryResult).not.toBeNull();
    expect(readQueryResult.data?.caseTemplate).not.toBeNull();
    const tasks = readQueryResult.data?.caseTemplate.tasks.edges;
    expect(tasks.length).toBeGreaterThan(0);
  });

  it('should delete relation in caseTemplate', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CaseTemplateRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        caseTemplateRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
          id
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: caseTemplateInternalId,
        toId: taskTemplateInternalId,
        relationship_type: 'template-task',
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.caseTemplateRelationDelete).toBeNull();
  });

  it('should taskTemplate deleted', async () => {
    const DELETE_TASK_QUERY = gql`
      mutation TaskTemplateDelete($id: ID!) {
        taskTemplateDelete(id: $id)
      }
    `;
    await queryAsAdmin({
      query: DELETE_TASK_QUERY,
      variables: { id: taskTemplateInternalId },
    });
    const queryResult = await queryAsAdmin({
      query: gql`
        query taskTemplate($id: String!) {
          taskTemplate(id: $id) {
            id
          }
        }
      `,
      variables: { id: taskTemplateInternalId }
    });
    expect(queryResult.data?.taskTemplate).toBeNull();
  });

  it('should caseTemplate deleted', async () => {
    const DELETE_QUERY = gql`
      mutation CaseTemplateDelete($id: ID!) {
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
