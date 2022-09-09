import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';

const LIST_QUERY = gql`
  query coursesOfAction(
    $first: Int
    $after: ID
    $orderBy: CoursesOfActionOrdering
    $orderMode: OrderingMode
    $filters: [CoursesOfActionFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    coursesOfAction(
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
  query courseOfAction($id: String!) {
    courseOfAction(id: $id) {
      id
      standard_id
      name
      description
      attackPatterns {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      toStix
    }
  }
`;

describe('CourseOfAction resolver standard behavior', () => {
  let courseOfActionInternalId;
  const courseOfActionStixId = 'course-of-action--1a80c59c-d839-4984-af04-04f3286d8f89';
  it('should courseOfAction created', async () => {
    const CREATE_QUERY = gql`
      mutation CourseOfActionAdd($input: CourseOfActionAddInput) {
        courseOfActionAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the courseOfAction
    const COURSE_OF_ACTION_TO_CREATE = {
      input: {
        name: 'CourseOfAction',
        stix_id: courseOfActionStixId,
        description: 'CourseOfAction description',
      },
    };
    const courseOfAction = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: COURSE_OF_ACTION_TO_CREATE,
    });
    expect(courseOfAction).not.toBeNull();
    expect(courseOfAction.data.courseOfActionAdd).not.toBeNull();
    expect(courseOfAction.data.courseOfActionAdd.name).toEqual('CourseOfAction');
    courseOfActionInternalId = courseOfAction.data.courseOfActionAdd.id;
  });
  it('should courseOfAction loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: courseOfActionInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.courseOfAction).not.toBeNull();
    expect(queryResult.data.courseOfAction.id).toEqual(courseOfActionInternalId);
    expect(queryResult.data.courseOfAction.toStix.length).toBeGreaterThan(5);
  });
  it('should courseOfAction loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: courseOfActionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.courseOfAction).not.toBeNull();
    expect(queryResult.data.courseOfAction.id).toEqual(courseOfActionInternalId);
  });
  it('should courseOfAction coursesOfAction be accurate', async () => {
    const courseOfAction = await elLoadById(ADMIN_USER, 'course-of-action--ae56a49d-5281-45c5-ab95-70a1439c338e');
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: courseOfAction.internal_id },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.courseOfAction).not.toBeNull();
    expect(queryResult.data.courseOfAction.standard_id).toEqual(
      'course-of-action--2d3af28d-aa36-59ad-ac57-65aa27664752'
    );
    expect(queryResult.data.courseOfAction.attackPatterns.edges.length).toEqual(1);
    expect(queryResult.data.courseOfAction.attackPatterns.edges[0].node.standard_id).toEqual(
      'attack-pattern--a01046cc-192f-5d52-8e75-6e447fae3890'
    );
  });
  it('should list coursesOfAction', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.coursesOfAction.edges.length).toEqual(2);
  });
  it('should update courseOfAction', async () => {
    const UPDATE_QUERY = gql`
      mutation CourseOfActionEdit($id: ID!, $input: [EditInput]!) {
        courseOfActionEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: courseOfActionInternalId, input: { key: 'name', value: ['CourseOfAction - test'] } },
    });
    expect(queryResult.data.courseOfActionEdit.fieldPatch.name).toEqual('CourseOfAction - test');
  });
  it('should context patch courseOfAction', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CourseOfActionEdit($id: ID!, $input: EditContext) {
        courseOfActionEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: courseOfActionInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.courseOfActionEdit.contextPatch.id).toEqual(courseOfActionInternalId);
  });
  it('should context clean courseOfAction', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation CourseOfActionEdit($id: ID!) {
        courseOfActionEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: courseOfActionInternalId },
    });
    expect(queryResult.data.courseOfActionEdit.contextClean.id).toEqual(courseOfActionInternalId);
  });
  it('should add relation in courseOfAction', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation CourseOfActionEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        courseOfActionEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on CourseOfAction {
                objectMarking {
                  edges {
                    node {
                      id
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: courseOfActionInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.courseOfActionEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in courseOfAction', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation CourseOfActionEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        courseOfActionEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: courseOfActionInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.courseOfActionEdit.relationDelete.objectMarking.edges.length).toEqual(0);
  });
  it('should courseOfAction deleted', async () => {
    const DELETE_QUERY = gql`
      mutation courseOfActionDelete($id: ID!) {
        courseOfActionEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the courseOfAction
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: courseOfActionInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: courseOfActionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.courseOfAction).toBeNull();
  });
});
