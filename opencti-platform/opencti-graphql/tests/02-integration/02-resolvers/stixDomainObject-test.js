import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { queryAsAdmin } from '../../utils/testQuery';
import { fileToReadStream } from '../../../src/database/file-storage';
import { MARKING_TLP_GREEN } from '../../../src/schema/identifier';

const LIST_QUERY = gql`
  query stixDomainObjects(
    $first: Int
    $after: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    stixDomainObjects(
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
          ... on Tool {
            name
            description
          }
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query stixDomainObject($id: String!) {
    stixDomainObject(id: $id) {
      id
      standard_id
      toStix
      editContext {
        focusOn
        name
      }
      ... on Tool {
        name
        description
      }
      importFiles{
        edges {
          node{
            id
            objectMarking {
              standard_id
            }
            metaData {
              description
            }
          }
        }
      }
    }
  }
`;

describe('StixDomainObject resolver standard behavior', () => {
  let stixDomainObjectInternalId;
  const stixDomainObjectStixId = 'tool--34c9875d-8206-4f4b-bf17-f58d9cf7ebec';
  it('should stixDomainObject created', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainObjectAdd($input: StixDomainObjectAddInput!) {
        stixDomainObjectAdd(input: $input) {
          id
          standard_id
          objectLabel {
            id
          }
          ... on Tool {
            name
            description
          }
        }
      }
    `;
    // Create the stixDomainObject
    const STIX_DOMAIN_ENTITY_TO_CREATE = {
      input: {
        name: 'StixDomainObject',
        type: 'Tool',
        stix_id: stixDomainObjectStixId,
        description: 'StixDomainObject description',
        objectLabel: ['TrickBot', 'COVID-19'],
      },
    };
    const stixDomainObject = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_DOMAIN_ENTITY_TO_CREATE,
    });
    expect(stixDomainObject).not.toBeNull();
    expect(stixDomainObject.data.stixDomainObjectAdd).not.toBeNull();
    expect(stixDomainObject.data.stixDomainObjectAdd.name).toEqual('StixDomainObject');
    expect(stixDomainObject.data.stixDomainObjectAdd.objectLabel.length).toEqual(2);
    stixDomainObjectInternalId = stixDomainObject.data.stixDomainObjectAdd.id;
  });
  it('should stixDomainObject upserted', async () => {
    const CREATE_QUERY = gql`
      mutation StixDomainObjectAdd($input: StixDomainObjectAddInput!) {
        stixDomainObjectAdd(input: $input) {
          id
          standard_id
          x_opencti_stix_ids
          objectLabel {
            id
          }
          ... on Tool {
            name
            description
          }
        }
      }
    `;
    // Create the stixDomainObject
    const STIX_DOMAIN_ENTITY_TO_CREATE = {
      input: {
        name: 'StixDomainObject',
        type: 'Tool',
        stix_id: 'tool--84dddb68-f440-4cb5-b9f6-a59159079ef5',
        description: 'StixDomainObject description',
        objectLabel: ['TrickBot', 'COVID-19'],
      },
    };
    const stixDomainObject = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_DOMAIN_ENTITY_TO_CREATE,
    });
    expect(stixDomainObject).not.toBeNull();
    expect(stixDomainObject.data.stixDomainObjectAdd).not.toBeNull();
    expect(stixDomainObject.data.stixDomainObjectAdd.name).toEqual('StixDomainObject');
    expect(stixDomainObject.data.stixDomainObjectAdd.objectLabel.length).toEqual(2);
    expect(stixDomainObject.data.stixDomainObjectAdd.x_opencti_stix_ids).toEqual(
      expect.arrayContaining(['tool--84dddb68-f440-4cb5-b9f6-a59159079ef5'])
    );
  });
  it('should stixDomainObject loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainObjectInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainObject).not.toBeNull();
    expect(queryResult.data.stixDomainObject.id).toEqual(stixDomainObjectInternalId);
    expect(queryResult.data.stixDomainObject.toStix.length).toBeGreaterThan(5);
  });
  it('should stixDomainObject loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainObjectStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainObject).not.toBeNull();
    expect(queryResult.data.stixDomainObject.id).toEqual(stixDomainObjectInternalId);
  });
  it('should list stixDomainObjects', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.stixDomainObjects.edges.length).toEqual(10);
  });
  it('should stixDomainObjects number to be accurate', async () => {
    const NUMBER_QUERY = gql`
      query stixDomainObjectsNumber {
        stixDomainObjectsNumber {
          total
        }
      }
    `;
    const queryResult = await queryAsAdmin({ query: NUMBER_QUERY });
    expect(queryResult.data.stixDomainObjectsNumber.total).toEqual(40);
  });
  it('should timeseries stixDomainObjects to be accurate', async () => {
    const TIMESERIES_QUERY = gql`
      query stixDomainObjectsTimeSeries(
        $types: [String]
        $field: String!
        $operation: StatsOperation!
        $startDate: DateTime!
        $endDate: DateTime!
        $interval: String!
      ) {
        stixDomainObjectsTimeSeries(
          types: $types
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
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'created',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.stixDomainObjectsTimeSeries.length).toEqual(13);
    expect(queryResult.data.stixDomainObjectsTimeSeries[1].value).toEqual(15);
    expect(queryResult.data.stixDomainObjectsTimeSeries[2].value).toEqual(5);
  });
  it('should update stixDomainObject', async () => {
    const UPDATE_QUERY = gql`
      mutation StixDomainObjectEdit($id: ID!, $input: [EditInput]!) {
        stixDomainObjectEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            ... on Tool {
              name
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixDomainObjectInternalId, input: { key: 'name', value: ['StixDomainObject - test'] } },
    });
    expect(queryResult.data.stixDomainObjectEdit.fieldPatch.name).toEqual('StixDomainObject - test');
  });
  it('should context patch stixDomainObject', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixDomainObjectEdit($id: ID!, $input: EditContext) {
        stixDomainObjectEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixDomainObjectInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.stixDomainObjectEdit.contextPatch.id).toEqual(stixDomainObjectInternalId);
  });
  it('should add and edit file on stixDomainObject', async () => {
    // Start by adding a file to stixDomainObject with importPush
    const IMPORT_FILE_QUERY = gql`
      mutation StixDomainObjectImportPush($id: ID!, $file: Upload!, $fileMarkings: [String]) {
        stixDomainObjectEdit(id: $id) {
          importPush(file: $file, fileMarkings: $fileMarkings) {
            id
          }
        }
      }
    `;
    const readStream = fileToReadStream('./tests/data/', 'test-file-to-index.txt', 'test-file-to-index.txt', 'text/plain');
    const fileUpload = { ...readStream, encoding: 'utf8' };
    const upload = new Upload();
    upload.promise = new Promise((executor) => {
      executor(fileUpload);
    });
    upload.file = fileUpload;
    const importPushQueryResult = await queryAsAdmin({
      query: IMPORT_FILE_QUERY,
      variables: { id: stixDomainObjectInternalId, file: upload, fileMarkings: [MARKING_TLP_GREEN] }
    });
    expect(importPushQueryResult.data.stixDomainObjectEdit.importPush.id).toBeDefined();
    const fileId = importPushQueryResult.data.stixDomainObjectEdit.importPush.id;
    // Edit this file with a description in stixDomainObject with a stixDomainObjectFileEdit mutation
    const EDIT_FILE_QUERY = gql`
      mutation StixDomainObjectFileEdit($id: ID!, $input: StixDomainObjectFileEditInput) {
        stixDomainObjectEdit(id: $id) {
          stixDomainObjectFileEdit(input: $input) {
            id
          }
        }
      }
    `;
    const fileDescription = 'TestDescription';
    const editFileQueryResult = await queryAsAdmin({
      query: EDIT_FILE_QUERY,
      variables: { id: stixDomainObjectInternalId, input: { id: fileId, description: fileDescription } }
    });
    expect(editFileQueryResult.data.stixDomainObjectEdit.stixDomainObjectFileEdit.id).toBeDefined();
    // Read the stixDomainObject and check that importFiles contain the added and edited file
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainObjectInternalId } });
    expect(queryResult.data.stixDomainObject.importFiles.edges.length).toBe(1);
    const importedFile = queryResult.data.stixDomainObject.importFiles.edges[0].node;
    expect(importedFile.id).toBe(fileId);
    expect(importedFile.objectMarking.length).toBe(1);
    expect(importedFile.objectMarking[0].standard_id).toBe(MARKING_TLP_GREEN);
    expect(importedFile.metaData.description).toBe(fileDescription);
  });
  it('should stixDomainObject editContext to be accurate', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainObjectInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainObject).not.toBeNull();
    expect(queryResult.data.stixDomainObject.id).toEqual(stixDomainObjectInternalId);
    expect(queryResult.data.stixDomainObject.editContext[0].focusOn).toEqual('description');
  });
  it('should context clean stixDomainObject', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation StixDomainObjectEdit($id: ID!) {
        stixDomainObjectEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: stixDomainObjectInternalId },
    });
    expect(queryResult.data.stixDomainObjectEdit.contextClean.id).toEqual(stixDomainObjectInternalId);
  });
  it('should add relation in stixDomainObject', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation StixDomainObjectEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        stixDomainObjectEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on StixDomainObject {
                objectMarking {
                  id
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
        id: stixDomainObjectInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.stixDomainObjectEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in stixDomainObject', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation StixDomainObjectEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        stixDomainObjectEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: stixDomainObjectInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.stixDomainObjectEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  it('should stixDomainObject deleted', async () => {
    const DELETE_QUERY = gql`
      mutation stixDomainObjectDelete($id: ID!) {
        stixDomainObjectEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the stixDomainObject
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixDomainObjectInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixDomainObjectStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixDomainObject).toBeNull();
  });
});
