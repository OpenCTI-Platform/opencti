import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, editorQuery, participantQuery, testContext } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { now } from '../../../src/utils/format';

const LIST_QUERY = gql`
  query opinions(
    $first: Int
    $after: ID
    $orderBy: OpinionsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    opinions(
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
          explanation
          authors
          opinion
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query opinionsTimeSeries(
    $objectId: String
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    opinionsTimeSeries(
      objectId: $objectId
      authorId: $authorId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const NUMBER_QUERY = gql`
  query opinionsNumber($objectId: String, $endDate: DateTime!) {
    opinionsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const DISTRIBUTION_QUERY = gql`
  query opinionsDistribution(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $order: String
  ) {
    opinionsDistribution(objectId: $objectId, field: $field, operation: $operation, limit: $limit, order: $order) {
      label
      value
      entity {
        ... on Identity {
          name
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query opinion($id: String!) {
    opinion(id: $id) {
      id
      standard_id
      explanation
      authors
      opinion
      toStix
    }
  }
`;

describe('Opinion resolver standard behavior', () => {
  let opinionInternalId;
  let datasetOpinionInternalId;
  let datasetMalwareInternalId;
  const opinionStixId = 'opinion--994491f0-f114-4e41-bcf0-3288c0324f53';
  it('should opinion created', async () => {
    const CREATE_QUERY = gql`
      mutation OpinionAdd($input: OpinionAddInput!) {
        opinionAdd(input: $input) {
          id
          standard_id
          explanation
          authors
          opinion
        }
      }
    `;
    // Create the opinion
    const OPINION_TO_CREATE = {
      input: {
        stix_id: opinionStixId,
        opinion: 'strongly-agree',
        explanation: 'Explanation of the opinion',
        objects: [
          'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
          'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
        ],
        createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
      },
    };
    const opinion = await editorQuery({
      query: CREATE_QUERY,
      variables: OPINION_TO_CREATE,
    });
    expect(opinion).not.toBeNull();
    expect(opinion.data.opinionAdd).not.toBeNull();
    expect(opinion.data.opinionAdd.explanation).toEqual('Explanation of the opinion');
    opinionInternalId = opinion.data.opinionAdd.id;
  });
  it('should opinion loaded by internal id', async () => {
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: opinionInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual(opinionInternalId);
    expect(queryResult.data.opinion.toStix.length).toBeGreaterThan(6);
  });
  it('should opinion loaded by stix id', async () => {
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: opinionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.id).toEqual(opinionInternalId);
  });
  it('should opinion stix objects sor stix relationships accurate', async () => {
    const opinion = await elLoadById(testContext, ADMIN_USER, 'opinion--fab0d63d-e1be-4771-9c14-043b76f71d4f');
    datasetOpinionInternalId = opinion.internal_id;
    const OPINION_STIX_DOMAIN_ENTITIES = gql`
      query opinion($id: String!) {
        opinion(id: $id) {
          id
          standard_id
          objects {
            edges {
              node {
                ... on BasicObject {
                  id
                  standard_id
                }
                ... on BasicRelationship {
                  id
                  standard_id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await editorQuery({
      query: OPINION_STIX_DOMAIN_ENTITIES,
      variables: { id: datasetOpinionInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).not.toBeNull();
    expect(queryResult.data.opinion.objects.edges.length).toEqual(5);
  });
  it('should opinion contains stix object or stix relationship accurate', async () => {
    const intrusionSet = await elLoadById(testContext, ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const stixRelationship = await elLoadById(testContext, ADMIN_USER, 'relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3');
    const OPINION_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP = gql`
      query opinionContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
        opinionContainsStixObjectOrStixRelationship(
          id: $id
          stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId
        )
      }
    `;
    let queryResult = await editorQuery({
      query: OPINION_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP,
      variables: {
        id: datasetOpinionInternalId,
        stixObjectOrStixRelationshipId: intrusionSet.internal_id,
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinionContainsStixObjectOrStixRelationship).not.toBeNull();
    expect(queryResult.data.opinionContainsStixObjectOrStixRelationship).toBeTruthy();
    queryResult = await editorQuery({
      query: OPINION_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP,
      variables: {
        id: datasetOpinionInternalId,
        stixObjectOrStixRelationshipId: stixRelationship.internal_id,
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinionContainsStixObjectOrStixRelationship).not.toBeNull();
    expect(queryResult.data.opinionContainsStixObjectOrStixRelationship).toBeTruthy();
  });
  it('should list opinions', async () => {
    const queryResult = await editorQuery({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.opinions.edges.length).toEqual(2);
  });
  it('should timeseries opinions to be accurate', async () => {
    const queryResult = await editorQuery({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.opinionsTimeSeries.length).toEqual(13);
    expect(queryResult.data.opinionsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.opinionsTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries opinions for entity to be accurate', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    datasetMalwareInternalId = malware.internal_id;
    const queryResult = await editorQuery({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: datasetMalwareInternalId,
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.opinionsTimeSeries.length).toEqual(13);
    expect(queryResult.data.opinionsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.opinionsTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries opinions for author to be accurate', async () => {
    const identity = await elLoadById(testContext, ADMIN_USER, 'identity--7b82b010-b1c0-4dae-981f-7756374a17df');
    const queryResult = await editorQuery({
      query: TIMESERIES_QUERY,
      variables: {
        authorId: identity.internal_id,
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.opinionsTimeSeries.length).toEqual(13);
    expect(queryResult.data.opinionsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.opinionsTimeSeries[3].value).toEqual(0);
  });
  it('should opinions number to be accurate', async () => {
    const queryResult = await editorQuery({
      query: NUMBER_QUERY,
      variables: {
        endDate: now(),
      },
    });
    expect(queryResult.data.opinionsNumber.total).toEqual(2);
    expect(queryResult.data.opinionsNumber.count).toEqual(2);
  });
  it('should opinions number by entity to be accurate', async () => {
    const queryResult = await editorQuery({
      query: NUMBER_QUERY,
      variables: {
        objectId: datasetMalwareInternalId,
        endDate: now(),
      },
    });
    expect(queryResult.data.opinionsNumber.total).toEqual(1);
    expect(queryResult.data.opinionsNumber.count).toEqual(1);
  });
  it('should opinions distribution to be accurate', async () => {
    const queryResult = await editorQuery({
      query: DISTRIBUTION_QUERY,
      variables: {
        field: 'created-by.internal_id',
        operation: 'count',
      },
    });
    expect(queryResult.data.opinionsDistribution.length).toEqual(0);
  });
  it('should opinions distribution by entity to be accurate', async () => {
    const queryResult = await editorQuery({
      query: DISTRIBUTION_QUERY,
      variables: {
        objectId: datasetMalwareInternalId,
        field: 'created-by.internal_id',
        operation: 'count',
      },
    });
    expect(queryResult.data.opinionsDistribution[0].entity.name).toEqual('ANSSI');
    expect(queryResult.data.opinionsDistribution[0].value).toEqual(1);
  });
  it('should update opinion', async () => {
    const UPDATE_QUERY = gql`
      mutation OpinionEdit($id: ID!, $input: [EditInput]!) {
        opinionEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            explanation
            authors
            opinion
          }
        }
      }
    `;
    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: opinionInternalId, input: { key: 'explanation', value: ['Opinion - test'] } },
    });
    expect(queryResult.data.opinionEdit.fieldPatch.explanation).toEqual('Opinion - test');
  });
  it('should context patch opinion', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OpinionEdit($id: ID!, $input: EditContext) {
        opinionEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await editorQuery({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: opinionInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.opinionEdit.contextPatch.id).toEqual(opinionInternalId);
  });
  it('should context clean opinion', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation OpinionEdit($id: ID!) {
        opinionEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await editorQuery({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: opinionInternalId },
    });
    expect(queryResult.data.opinionEdit.contextClean.id).toEqual(opinionInternalId);
  });
  it('should add relation in opinion', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation OpinionEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        opinionEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Opinion {
                objectMarking {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await editorQuery({
      query: RELATION_ADD_QUERY,
      variables: {
        id: opinionInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.opinionEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in opinion', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation OpinionEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        opinionEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await editorQuery({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: opinionInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.opinionEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should opinion deleted', async () => {
    const DELETE_QUERY = gql`
      mutation opinionDelete($id: ID!) {
        opinionEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the opinion
    await editorQuery({
      query: DELETE_QUERY,
      variables: { id: opinionInternalId },
    });
    // Verify is no longer found
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: opinionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).toBeNull();
  });
});

describe('Opinion resolver behavior with Participant and Editor users', () => {
  const participantOpinionStixId = 'opinion--4f5dec39-9b56-4175-8ad8-b5588672915f';
  const editorOpinionStixId = 'opinion--ac3aeb26-47c1-43b7-b12d-b8be102aaff1';
  let participantId;

  it('Participant should create opinion', async () => {
    const CREATE_QUERY = gql`
        mutation OpinionAdd($input: OpinionUserAddInput!) {
            userOpinionAdd(input: $input) {
                id
                opinion
                createdBy {
                    id
                    name
                }
            }
        }
    `;

    // Create the opinion
    const OPINION_TO_CREATE = {
      input: {
        stix_id: participantOpinionStixId,
        opinion: 'agree',
        explanation: 'Explanation of the opinion',
        objects: [
        ]
      },
    };

    const queryResult = await participantQuery({
      query: CREATE_QUERY,
      variables: OPINION_TO_CREATE,
    });

    expect(queryResult.data.userOpinionAdd.opinion).toEqual('agree');
  });

  it('Participant should update his own opinion', async () => {
    const UPDATE_QUERY = gql`
        mutation OpinionEdit($id: ID!, $input: [EditInput]!) {
            opinionEdit(id: $id) {
                fieldPatch(input: $input) {
                    id
                    opinion
                    createdBy {
                        id
                        name
                    }
                }
            }
        }
    `;

    const queryResult = await participantQuery({
      query: UPDATE_QUERY,
      variables: { id: participantOpinionStixId, input: { key: 'opinion', value: ['disagree'] } },
    });

    expect(queryResult.data.opinionEdit.fieldPatch.opinion).toEqual('disagree');
    participantId = queryResult.data.opinionEdit.fieldPatch.createdBy.id;
  });

  it('Participant should delete his own opinion', async () => {
    const DELETE_QUERY = gql`
        mutation opinionDelete($id: ID!) {
            opinionEdit(id: $id) {
                delete
            }
        }
    `;
    // Delete the opinion
    await participantQuery({
      query: DELETE_QUERY,
      variables: { id: participantOpinionStixId },
    });
    // Verify is no longer found
    const queryResult = await participantQuery({ query: READ_QUERY, variables: { id: participantOpinionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).toBeNull();
  });

  it('Editor should create opinion', async () => {
    const CREATE_QUERY = gql`
        mutation OpinionAdd($input: OpinionAddInput!) {
            opinionAdd(input: $input) {
                id
                createdBy {
                    id
                    name
                }
                opinion
            }
        }
    `;

    // Create the opinion
    const OPINION_TO_CREATE = {
      input: {
        stix_id: editorOpinionStixId,
        opinion: 'agree',
        explanation: 'Explanation of the opinion',
        objects: [
        ],
        createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
      },
    };

    const queryResult = await editorQuery({
      query: CREATE_QUERY,
      variables: OPINION_TO_CREATE,
    });
    expect(queryResult.data.opinionAdd.opinion).toEqual('agree');
  });

  it('Participant should not update Editor opinion', async () => {
    const UPDATE_QUERY = gql`
        mutation OpinionEdit($id: ID!, $input: [EditInput]!) {
            opinionEdit(id: $id) {
                fieldPatch(input: $input) {
                    id
                    explanation
                    authors
                    opinion
                }
            }
        }
    `;

    const queryResult = await participantQuery({
      query: UPDATE_QUERY,
      variables: { id: editorOpinionStixId, input: { key: 'opinion', value: 'agree' } },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.errors.length).toEqual(1);
    expect(queryResult.errors.at(0).extensions?.code).toEqual('FORBIDDEN_ACCESS');
  });

  it('Editor should update his own opinion', async () => {
    const UPDATE_QUERY = gql`
        mutation OpinionEdit($id: ID!, $input: [EditInput]!) {
            opinionEdit(id: $id) {
                fieldPatch(input: $input) {
                    id
                    explanation
                    authors
                    opinion
                    createdBy {
                        id
                    }
                }
            }
        }
    `;

    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: editorOpinionStixId, input: [{ key: 'authors', value: [participantId] }] },
    });
    expect(queryResult.data.opinionEdit.fieldPatch.authors[0]).toEqual(participantId);
  });

  it('Editor should update Participant opinion', async () => {
    const UPDATE_QUERY = gql`
        mutation OpinionEdit($id: ID!, $input: [EditInput]!) {
            opinionEdit(id: $id) {
                fieldPatch(input: $input) {
                    id
                    explanation
                    authors
                    opinion
                    createdBy {
                        id
                    }
                }
            }
        }
    `;

    const queryResult = await editorQuery({
      query: UPDATE_QUERY,
      variables: { id: editorOpinionStixId, input: { key: 'opinion', value: 'neutral' } },
    });
    expect(queryResult.data.opinionEdit.fieldPatch.opinion).toEqual('neutral');
  });

  it('Editor should delete Participant opinion', async () => {
    const DELETE_QUERY = gql`
        mutation opinionDelete($id: ID!) {
            opinionEdit(id: $id) {
                delete
            }
        }
    `;
    // Delete the opinion
    await editorQuery({
      query: DELETE_QUERY,
      variables: { id: editorOpinionStixId },
    });
    // Verify is no longer found
    const queryResult = await editorQuery({ query: READ_QUERY, variables: { id: editorOpinionStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.opinion).toBeNull();
  });
});
