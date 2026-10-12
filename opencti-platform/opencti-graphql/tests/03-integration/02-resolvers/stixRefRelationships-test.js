import { afterAll, beforeAll, expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { now } from 'moment';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../../src/schema/general';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../../../src/modules/malwareAnalysis/malwareAnalysis-types';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_SOFTWARE } from '../../../src/schema/stixCyberObservable';

describe('StixRefRelationship', () => {
  let stixRefRelationshipInternalId;
  let stixRefRelationshipCreatedAt;
  it('should StixRefRelationship created', async () => {
    const CREATE_QUERY = gql`
            mutation StixDomainRelationAdd($input: StixRefRelationshipAddInput!) {
                stixRefRelationshipAdd(input: $input) {
                    id
                    spec_version
                    created_at
                    updated_at
                    refreshed_at
                    confidence
                    from {
                        ... on Malware {
                            id
                            x_opencti_stix_ids
                        }
                    }
                }
            }
        `;
    // Create the stixRefRelationship
    const STIX_RELATION_TO_CREATE = {
      input: {
        fromId: 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
        toId: 'software--b0debdba-74e7-4463-ad2a-34334ee66d8d',
        relationship_type: 'operating-system',
        confidence: 90,
      },
    };
    const stixRefRelationship = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: STIX_RELATION_TO_CREATE,
    });

    expect(stixRefRelationship.data.stixRefRelationshipAdd).not.toBeNull();
    expect(stixRefRelationship.data.stixRefRelationshipAdd.spec_version).toEqual('2.1');
    expect(stixRefRelationship.data.stixRefRelationshipAdd.confidence).toEqual(90);
    expect(stixRefRelationship.data.stixRefRelationshipAdd.from.x_opencti_stix_ids[0]).toEqual('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    stixRefRelationshipInternalId = stixRefRelationship.data.stixRefRelationshipAdd.id;
    stixRefRelationshipCreatedAt = stixRefRelationship.data.stixRefRelationshipAdd.created_at;
    expect(stixRefRelationshipCreatedAt).toEqual(stixRefRelationship.data.stixRefRelationshipAdd.updated_at);
    expect(stixRefRelationshipCreatedAt).toEqual(stixRefRelationship.data.stixRefRelationshipAdd.refreshed_at);
  });
  it('should StixRefRelationship updated', async () => {
    const UPDATE_QUERY = gql`
      mutation StixDomainRelationUpdate($id: ID!, $input: [EditInput!]!) {
        stixRefRelationshipEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            created_at
            updated_at
            confidence
            refreshed_at
          }
        }
      }
    `;
    // Update the stixRefRelationship
    const editInput = [{ key: 'confidence', value: '50' }];
    const editionStartDatetime = now();
    const stixRefRelationship = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: stixRefRelationshipInternalId, input: editInput },
    });

    expect(stixRefRelationship.data.stixRefRelationshipEdit.fieldPatch).not.toBeNull();
    // should modify confidence
    expect(stixRefRelationship.data.stixRefRelationshipEdit.fieldPatch.confidence).toEqual(50);
    // should modify updated_at
    expect(editionStartDatetime < stixRefRelationship.data.stixRefRelationshipEdit.fieldPatch.updated_at).toBeTruthy();
    expect(stixRefRelationshipCreatedAt < stixRefRelationship.data.stixRefRelationshipEdit.fieldPatch.updated_at).toBeTruthy();
    // should modify refreshed_at
    expect(stixRefRelationship.data.stixRefRelationshipEdit.fieldPatch.updated_at).toEqual(stixRefRelationship.data.stixRefRelationshipEdit.fieldPatch.refreshed_at);
  });
  it('should stixRefRelationship deleted', async () => {
    const READ_QUERY = gql`
            query stixRefRelationship($id: String!) {
                stixRefRelationship(id: $id) {
                    id
                }
            }
        `;
    const DELETE_QUERY = gql`
          mutation stixRefRelationshipDelete($id: ID!) {
              stixRefRelationshipEdit(id: $id) {
                  delete
              }
          }
      `;
    // Delete the stixRefRelationship
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: stixRefRelationshipInternalId },
    });
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: stixRefRelationshipInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.stixRefRelationship).toBeNull();
  });
  it('should return allowed types for a rel relationship with a given type', async () => {
    // Malware Analysis
    const ALLOWED_TYPES_QUERY = gql`
        query allowedRefRelationshipTypesQuery($type: String!) {
            stixSchemaRefRelationshipsPossibleTypes(type: $type)
        }
    `;
    const queryResult1 = await queryAsAdmin({
      query: ALLOWED_TYPES_QUERY,
      variables: { type: ENTITY_TYPE_MALWARE_ANALYSIS },
    });
    expect(queryResult1.data.stixSchemaRefRelationshipsPossibleTypes.length).toEqual(1);
    expect(queryResult1.data.stixSchemaRefRelationshipsPossibleTypes[0]).toEqual(ABSTRACT_STIX_CYBER_OBSERVABLE);
    // Malware
    const queryResult2 = await queryAsAdmin({
      query: ALLOWED_TYPES_QUERY,
      variables: { type: 'Malware' },
    });
    expect(queryResult2.data.stixSchemaRefRelationshipsPossibleTypes.length).toEqual(3);
    expect(queryResult2.data.stixSchemaRefRelationshipsPossibleTypes.includes(ENTITY_HASHED_OBSERVABLE_STIX_FILE)).toBeTruthy();
    expect(queryResult2.data.stixSchemaRefRelationshipsPossibleTypes.includes(ENTITY_SOFTWARE)).toBeTruthy();
    expect(queryResult2.data.stixSchemaRefRelationshipsPossibleTypes.includes(ENTITY_HASHED_OBSERVABLE_ARTIFACT)).toBeTruthy();
    // File
    const queryResult3 = await queryAsAdmin({
      query: ALLOWED_TYPES_QUERY,
      variables: { type: ENTITY_HASHED_OBSERVABLE_STIX_FILE },
    });
    expect(queryResult3.data.stixSchemaRefRelationshipsPossibleTypes.length).toEqual(1);
    expect(queryResult3.data.stixSchemaRefRelationshipsPossibleTypes[0]).toEqual(ABSTRACT_STIX_CORE_OBJECT);
  });
});

describe('StixRefRelationship added again on a single ref', () => {
  const OBSERVABLE_ADD_QUERY = gql`
    mutation StixCyberObservableAdd($type: String!, $createdBy: String, $StixFile: StixFileAddInput, $Directory: DirectoryAddInput) {
      stixCyberObservableAdd(type: $type, createdBy: $createdBy, StixFile: $StixFile, Directory: $Directory) {
        id
      }
    }
  `;
  const OBSERVABLE_DELETE_QUERY = gql`
    mutation StixCyberObservableDelete($id: ID!) {
      stixCyberObservableEdit(id: $id) {
        delete
      }
    }
  `;
  const REF_ADD_QUERY = gql`
    mutation StixRefRelationshipAdd($input: StixRefRelationshipAddInput!) {
      stixRefRelationshipAdd(input: $input) {
        id
        to {
          ... on BasicObject {
            id
          }
        }
      }
    }
  `;
  const FILE_REFS_QUERY = gql`
    query StixFileRefs($id: String!, $fromId: StixRef) {
      stixCyberObservable(id: $id) {
        createdBy {
          id
        }
      }
      stixNestedRefRelationships(fromId: $fromId, relationship_type: ["parent-directory"]) {
        edges {
          node {
            id
            to {
              ... on BasicObject {
                id
              }
            }
          }
        }
      }
    }
  `;
  const ANSSI = 'identity--7b82b010-b1c0-4dae-981f-7756374a17df';
  const JOHN_DOE = 'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f';
  let directoryAId;
  let directoryBId;
  let fileId;
  let firstParentRelationId;

  const addDirectory = async (path) => {
    const { data } = await queryAsAdminWithSuccess({ query: OBSERVABLE_ADD_QUERY, variables: { type: 'Directory', Directory: { path } } });
    return data.stixCyberObservableAdd.id;
  };
  // Same calls as the python client for a file with a parent_directory_ref: the file upsert, then the nested ref
  const importFileUnder = async (directoryId) => {
    const StixFile = { name: 'single-ref-test.exe', hashes: [{ algorithm: 'MD5', hash: '5ad1e5ad1e5ad1e5ad1e5ad1e5ad1e50' }] };
    const { data } = await queryAsAdminWithSuccess({ query: OBSERVABLE_ADD_QUERY, variables: { type: 'StixFile', createdBy: ANSSI, StixFile } });
    fileId = data.stixCyberObservableAdd.id;
    const input = { fromId: fileId, toId: directoryId, relationship_type: 'parent-directory' };
    const { data: refData } = await queryAsAdminWithSuccess({ query: REF_ADD_QUERY, variables: { input } });
    return refData.stixRefRelationshipAdd;
  };
  const loadFileRefs = async () => {
    const { data } = await queryAsAdminWithSuccess({ query: FILE_REFS_QUERY, variables: { id: fileId, fromId: fileId } });
    return {
      createdById: data.stixCyberObservable.createdBy?.id,
      parentRelations: data.stixNestedRefRelationships.edges.map(({ node }) => ({ id: node.id, toId: node.to.id })),
    };
  };
  const addCreatedBy = async (identityId) => {
    const input = { fromId: fileId, toId: identityId, relationship_type: 'created-by' };
    const { data } = await queryAsAdminWithSuccess({ query: REF_ADD_QUERY, variables: { input } });
    return data.stixRefRelationshipAdd;
  };

  beforeAll(async () => {
    directoryAId = await addDirectory('C:\\single-ref-test\\A');
    directoryBId = await addDirectory('C:\\single-ref-test\\B');
  });

  afterAll(async () => {
    for (const id of [fileId, directoryAId, directoryBId]) {
      await queryAsAdmin({ query: OBSERVABLE_DELETE_QUERY, variables: { id } });
    }
  });

  it('should set the parent directory on the first import', async () => {
    const relation = await importFileUnder(directoryAId);
    expect(relation.to.id).toEqual(directoryAId);
    firstParentRelationId = relation.id;
    const { parentRelations } = await loadFileRefs();
    expect(parentRelations).toEqual([{ id: firstParentRelationId, toId: directoryAId }]);
  });

  it('should keep the parent directory when the file is imported again under the same directory', async () => {
    const relation = await importFileUnder(directoryAId);
    expect(relation.id).toEqual(firstParentRelationId);
    expect(relation.to.id).toEqual(directoryAId);
    const { parentRelations } = await loadFileRefs();
    expect(parentRelations).toEqual([{ id: firstParentRelationId, toId: directoryAId }]);
  });

  it('should replace the parent directory when the file is imported under another directory', async () => {
    const relation = await importFileUnder(directoryBId);
    expect(relation.id).not.toEqual(firstParentRelationId);
    expect(relation.to.id).toEqual(directoryBId);
    const { parentRelations } = await loadFileRefs();
    expect(parentRelations).toEqual([{ id: relation.id, toId: directoryBId }]);
  });

  it('should keep then replace the author the same way', async () => {
    const { createdById: anssiId } = await loadFileRefs();
    expect(anssiId).toBeDefined();
    const sameAuthor = await addCreatedBy(ANSSI);
    expect(sameAuthor.to.id).toEqual(anssiId);
    expect((await loadFileRefs()).createdById).toEqual(anssiId);
    const otherAuthor = await addCreatedBy(JOHN_DOE);
    expect(otherAuthor.to.id).not.toEqual(anssiId);
    expect((await loadFileRefs()).createdById).toEqual(otherAuthor.to.id);
  });
});
