import { afterAll, beforeAll, expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { now } from 'moment';
import { queryAsAdmin, queryAsAdminWithError, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createRelation, createRelationRaw } from '../../../src/database/middleware';
import { fullRelationsList } from '../../../src/database/middleware-loader';
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
        start_time
        stop_time
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
        updated_at
        createdBy {
          id
        }
      }
      stixNestedRefRelationships(fromId: $fromId, relationship_type: ["parent-directory"]) {
        edges {
          node {
            id
            start_time
            stop_time
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
  const ORGANIZATION_ADD_QUERY = gql`
    mutation OrganizationAdd($input: OrganizationAddInput!) {
      organizationAdd(input: $input) {
        id
        createdBy {
          id
        }
      }
    }
  `;
  const ORGANIZATION_DELETE_QUERY = gql`
    mutation OrganizationDelete($id: ID!) {
      organizationDelete(id: $id)
    }
  `;
  const ORGANIZATION_AUTHOR_QUERY = gql`
    query OrganizationAuthor($id: String!) {
      organization(id: $id) {
        createdBy {
          id
        }
      }
    }
  `;
  const FILE_MARKINGS_QUERY = gql`
    query StixFileMarkings($id: String!) {
      stixCyberObservable(id: $id) {
        objectMarking {
          id
        }
      }
    }
  `;
  const TLP_GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da';
  const TLP_AMBER = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82';
  const ANSSI = 'identity--7b82b010-b1c0-4dae-981f-7756374a17df';
  const JOHN_DOE = 'identity--d37acc64-4a6f-4dc2-879a-a4c138d0a27f';
  let directoryAId;
  let directoryBId;
  let directoryCId;
  let fileId;
  let firstParentRelationId;
  let authorId;
  let authoredId;

  const addDirectory = async (path) => {
    const { data } = await queryAsAdminWithSuccess({ query: OBSERVABLE_ADD_QUERY, variables: { type: 'Directory', Directory: { path } } });
    return data.stixCyberObservableAdd.id;
  };
  const addOrganization = async (name, createdBy) => {
    const { data } = await queryAsAdminWithSuccess({ query: ORGANIZATION_ADD_QUERY, variables: { input: { name, createdBy } } });
    return data.organizationAdd;
  };
  const upsertFile = async () => {
    const StixFile = { name: 'single-ref-test.exe', hashes: [{ algorithm: 'MD5', hash: '5ad1e5ad1e5ad1e5ad1e5ad1e5ad1e50' }] };
    const { data } = await queryAsAdminWithSuccess({ query: OBSERVABLE_ADD_QUERY, variables: { type: 'StixFile', createdBy: ANSSI, StixFile } });
    fileId = data.stixCyberObservableAdd.id;
  };
  const addRef = async (toId, relationshipType, dates = {}) => {
    const input = { fromId: fileId, toId, relationship_type: relationshipType, ...dates };
    const { data } = await queryAsAdminWithSuccess({ query: REF_ADD_QUERY, variables: { input } });
    return data.stixRefRelationshipAdd;
  };
  // Same calls as the python client for a file with a parent_directory_ref: the file upsert, then the nested ref
  const importFileUnder = async (directoryId) => {
    await upsertFile();
    return addRef(directoryId, 'parent-directory');
  };
  const loadFileRefs = async () => {
    const { data } = await queryAsAdminWithSuccess({ query: FILE_REFS_QUERY, variables: { id: fileId, fromId: fileId } });
    return {
      createdById: data.stixCyberObservable.createdBy?.id,
      updatedAt: data.stixCyberObservable.updated_at,
      parentRelations: data.stixNestedRefRelationships.edges.map(({ node }) => ({ id: node.id, toId: node.to.id })),
      parentDates: data.stixNestedRefRelationships.edges.map(({ node }) => ({
        start_time: new Date(node.start_time).toISOString(),
        stop_time: new Date(node.stop_time).toISOString(),
      })),
    };
  };

  beforeAll(async () => {
    directoryAId = await addDirectory('C:\\single-ref-test\\A');
    directoryBId = await addDirectory('C:\\single-ref-test\\B');
    directoryCId = await addDirectory('C:\\single-ref-test\\C');
  });

  afterAll(async () => {
    for (const id of [fileId, directoryAId, directoryBId, directoryCId]) {
      await queryAsAdmin({ query: OBSERVABLE_DELETE_QUERY, variables: { id } });
    }
    for (const id of [authoredId, authorId]) {
      await queryAsAdmin({ query: ORGANIZATION_DELETE_QUERY, variables: { id } });
    }
  });

  it('should set the parent directory on the first import', async () => {
    const relation = await importFileUnder(directoryAId);
    expect(relation.to.id).toEqual(directoryAId);
    firstParentRelationId = relation.id;
    const { parentRelations } = await loadFileRefs();
    expect(parentRelations).toEqual([{ id: firstParentRelationId, toId: directoryAId }]);
  });

  it('should keep the parent directory without updating the file when it is imported again under the same directory', async () => {
    await upsertFile();
    const { updatedAt } = await loadFileRefs();
    const relation = await addRef(directoryAId, 'parent-directory');
    expect(relation.id).toEqual(firstParentRelationId);
    expect(relation.to.id).toEqual(directoryAId);
    const refs = await loadFileRefs();
    expect(refs.parentRelations).toEqual([{ id: firstParentRelationId, toId: directoryAId }]);
    expect(refs.updatedAt).toEqual(updatedAt);
  });

  it('should replace the parent directory when the file is imported under another directory', async () => {
    const relation = await importFileUnder(directoryBId);
    expect(relation.id).not.toEqual(firstParentRelationId);
    expect(relation.to.id).toEqual(directoryBId);
    const { parentRelations } = await loadFileRefs();
    expect(parentRelations).toEqual([{ id: relation.id, toId: directoryBId }]);
  });

  it('should keep the dates of the input when the parent directory is replaced', async () => {
    const dates = { start_time: '2026-01-01T00:00:00.000Z', stop_time: '2026-06-01T00:00:00.000Z' };
    const invalidInput = { fromId: fileId, toId: directoryAId, relationship_type: 'parent-directory', start_time: dates.stop_time, stop_time: dates.start_time };
    await queryAsAdminWithError({ query: REF_ADD_QUERY, variables: { input: invalidInput } }, 'You cant create a relation with a stop_time less than the start_time');
    expect((await loadFileRefs()).parentRelations.map(({ toId }) => toId)).toEqual([directoryBId]);
    const relation = await addRef(directoryAId, 'parent-directory', dates);
    expect(relation.to.id).toEqual(directoryAId);
    expect(new Date(relation.start_time).toISOString()).toEqual(dates.start_time);
    expect(new Date(relation.stop_time).toISOString()).toEqual(dates.stop_time);
    const { parentRelations } = await loadFileRefs();
    expect(parentRelations).toEqual([{ id: relation.id, toId: directoryAId }]);
  });

  it('should serialize concurrent replacements of the parent directory', async () => {
    const datesOne = { start_time: '2026-02-01T00:00:00.000Z', stop_time: '2026-03-01T00:00:00.000Z' };
    const datesTwo = { start_time: '2026-04-01T00:00:00.000Z', stop_time: '2026-05-01T00:00:00.000Z' };
    // Same target: one call replaces, the other finds the target already set and changes nothing
    const sameTarget = await Promise.all([addRef(directoryBId, 'parent-directory', datesOne), addRef(directoryBId, 'parent-directory', datesTwo)]);
    expect(sameTarget[1].id).toEqual(sameTarget[0].id);
    const refsAfterSameTarget = await loadFileRefs();
    expect(refsAfterSameTarget.parentRelations).toEqual([{ id: sameTarget[0].id, toId: directoryBId }]);
    expect([datesOne, datesTwo]).toContainEqual(refsAfterSameTarget.parentDates[0]);
    // Different targets: the last replacement wins, with its own dates
    const requests = [{ toId: directoryAId, dates: datesOne }, { toId: directoryCId, dates: datesTwo }];
    await Promise.all(requests.map(({ toId, dates }) => addRef(toId, 'parent-directory', dates)));
    const refsAfterOtherTargets = await loadFileRefs();
    expect(refsAfterOtherTargets.parentRelations).toHaveLength(1);
    const winner = requests.find(({ toId }) => toId === refsAfterOtherTargets.parentRelations[0].toId);
    expect(refsAfterOtherTargets.parentDates[0]).toEqual(winner.dates);
  });

  it('should keep then replace the author the same way', async () => {
    const { createdById: anssiId, updatedAt } = await loadFileRefs();
    expect(anssiId).toBeDefined();
    const sameAuthor = await addRef(ANSSI, 'created-by');
    expect(sameAuthor.to.id).toEqual(anssiId);
    const refsAfterSameAuthor = await loadFileRefs();
    expect(refsAfterSameAuthor.createdById).toEqual(anssiId);
    expect(refsAfterSameAuthor.updatedAt).toEqual(updatedAt);
    const otherAuthor = await addRef(JOHN_DOE, 'created-by');
    expect(otherAuthor.to.id).not.toEqual(anssiId);
    expect((await loadFileRefs()).createdById).toEqual(otherAuthor.to.id);
  });

  it('should not replace the author of an element by an element it authors', async () => {
    const author = await addOrganization('single-ref-test author', ANSSI);
    authorId = author.id;
    const authored = await addOrganization('single-ref-test authored', authorId);
    authoredId = authored.id;
    const input = { fromId: authorId, toId: authoredId, relationship_type: 'created-by' };
    await queryAsAdminWithError({ query: REF_ADD_QUERY, variables: { input } }, 'You cant create a cyclic relation');
    const { data } = await queryAsAdminWithSuccess({ query: ORGANIZATION_AUTHOR_QUERY, variables: { id: authorId } });
    expect(data.organization.createdBy.id).toEqual(author.createdBy.id);
  });

  it('should never let a restoration overwrite the current target', async () => {
    const { createdById } = await loadFileRefs();
    const input = { fromId: fileId, toId: ANSSI, relationship_type: 'created-by' };
    await expect(createRelation(testContext, ADMIN_USER, input, { restore: true })).rejects.toThrow('Cant add another relation on single ref');
    expect((await loadFileRefs()).createdById).toEqual(createdById);
  });

  const countAuthorRelations = async () => (await fullRelationsList(testContext, ADMIN_USER, 'created-by', { fromId: fileId })).length;

  it('should replace the author the same way when the ref is created without event', async () => {
    // Without event the from of a multiple ref is resolved without its refs; a single ref must still see its current target
    await addRef(JOHN_DOE, 'created-by');
    const { createdById } = await loadFileRefs();
    const input = { fromId: fileId, toId: ANSSI, relationship_type: 'created-by' };
    await createRelationRaw(testContext, ADMIN_USER, input, { publishStreamEvent: false });
    const authorRelations = await fullRelationsList(testContext, ADMIN_USER, 'created-by', { fromId: fileId });
    expect(authorRelations).toHaveLength(1);
    const { createdById: newAuthorId } = await loadFileRefs();
    expect(newAuthorId).toBeDefined();
    expect(newAuthorId).not.toEqual(createdById);
    expect(authorRelations[0].toId).toEqual(newAuthorId);
  });

  it('should keep the author without event when the same one is added again', async () => {
    await addRef(ANSSI, 'created-by');
    const { createdById } = await loadFileRefs();
    const input = { fromId: fileId, toId: ANSSI, relationship_type: 'created-by' };
    const result = await createRelationRaw(testContext, ADMIN_USER, input, { publishStreamEvent: false });
    expect(result.isCreation).toBe(false);
    expect(await countAuthorRelations()).toBe(1);
    expect((await loadFileRefs()).createdById).toEqual(createdById);
  });

  it('should never let a restoration without event overwrite the current author', async () => {
    const { createdById } = await loadFileRefs();
    const input = { fromId: fileId, toId: JOHN_DOE, relationship_type: 'created-by' };
    await expect(createRelationRaw(testContext, ADMIN_USER, input, { restore: true, publishStreamEvent: false })).rejects.toThrow('Cant add another relation on single ref');
    expect(await countAuthorRelations()).toBe(1);
    expect((await loadFileRefs()).createdById).toEqual(createdById);
  });

  it('should create a multiple ref without event, then find it again', async () => {
    // Multiple refs without event take the light resolution of the from
    await addRef(ANSSI, 'created-by');
    expect((await loadFileRefs()).createdById).toBeDefined();
    const input = { fromId: fileId, toId: TLP_GREEN, relationship_type: 'object-marking' };
    const created = await createRelationRaw(testContext, ADMIN_USER, input, { publishStreamEvent: false });
    expect(created.isCreation).toBe(true);
    expect(created.event).toBeUndefined();
    // Light resolution: the file has an author, which only the full resolution of the from would carry
    expect(created.element.from.createdBy).toBeUndefined();
    const markingRelations = await fullRelationsList(testContext, ADMIN_USER, 'object-marking', { fromId: fileId });
    expect(markingRelations).toHaveLength(1);
    const { data } = await queryAsAdminWithSuccess({ query: FILE_MARKINGS_QUERY, variables: { id: fileId } });
    expect(data.stixCyberObservable.objectMarking.map((m) => m.id)).toEqual([markingRelations[0].toId]);
    const again = await createRelationRaw(testContext, ADMIN_USER, input, { publishStreamEvent: false });
    expect(again.isCreation).toBeFalsy();
    expect(await fullRelationsList(testContext, ADMIN_USER, 'object-marking', { fromId: fileId })).toHaveLength(1);
  });

  it('should check the commit references of a multiple ref created without event', async () => {
    const input = { fromId: fileId, toId: TLP_AMBER, relationship_type: 'object-marking' };
    const opts = { publishStreamEvent: false, references: ['external-reference--00000000-0000-4000-8000-000000000000'] };
    await expect(createRelationRaw(testContext, ADMIN_USER, input, opts)).rejects.toThrow('Cant find element references for commit');
  });
});
