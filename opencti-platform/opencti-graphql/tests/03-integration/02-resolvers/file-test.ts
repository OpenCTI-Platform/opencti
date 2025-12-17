import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { fileToReadStream } from '../../../src/database/file-storage';
import Upload from 'graphql-upload/Upload.mjs';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

describe('File resolver standard behavior', () => {
  // TODO: this test suite should address all queries and mutations from src/resolvers/file.js

  it('should guess mimetypes correctly', async () => {
    const GUESS_MIMETYPE_QUERY = gql`
      query guessMimeType {
        file1: guessMimeType(fileId: "pdf_report")
        file2: guessMimeType(fileId: "path/1/file.yar")
        file3: guessMimeType(fileId: "path/to/iamajsonfile.json")
        file4: guessMimeType(fileId: "path/to/iamapdf.pdf")
        file5: guessMimeType(fileId: "path/to/i Have space and 💖.txt")
        file6: guessMimeType(fileId: "unknown")
        file7: guessMimeType(fileId: "export/Malware/b4bebef0-7f1b-4212-b09d-f376adb3181a/(ExportFileStix)_Malware-Paradise Ransomware_all.json")
      }
    `;
    const queryResult = await queryAsAdmin({
      query: GUESS_MIMETYPE_QUERY,
    });

    expect(queryResult.data?.file1).toBe('application/pdf');
    expect(queryResult.data?.file2).toBe('text/yara+plain');
    expect(queryResult.data?.file3).toBe('application/json');
    expect(queryResult.data?.file4).toBe('application/pdf');
    expect(queryResult.data?.file5).toBe('text/plain');
    expect(queryResult.data?.file6).toBe('application/octet-stream');
    expect(queryResult.data?.file7).toBe('application/json');
  });

  describe('batchFileMarkingDefinitions', () => {
    it('should filter empty markings correctly', async () => {
      // First step : Create a marking definition
      const CREATE_MARKING_QUERY = gql`
        mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput!) {
            markingDefinitionAdd(input: $input) {
                id
                definition_type
                definition
            }
        }
    `;
      const customMarkingId = 'marking-definition--35ee3df2-dc60-4bf3-9b57-98222b827a86';
      const MARKING_DEFINITION_TO_CREATE = {
        input: {
          stix_id: customMarkingId,
          definition_type: 'TLP',
          definition: 'TLP:TEST_DELETE',
          x_opencti_order: 0,
        },
      };
      const markingDefinition = await queryAsAdminWithSuccess({
        query: CREATE_MARKING_QUERY,
        variables: MARKING_DEFINITION_TO_CREATE,
      });

      const markingDefinitionInternalId = markingDefinition?.data?.markingDefinitionAdd.id;

      expect(markingDefinitionInternalId).toBeDefined();
      expect(markingDefinition?.data?.markingDefinitionAdd.definition).toEqual('TLP:TEST_DELETE');

      // Second step : import file
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
      const stixDomainObjectStixId = 'tool--34c9875d-8206-4f4b-bf17-f58d9cf7ebec';
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

      // Third step : Create the stixDomainObject
      const STIX_DOMAIN_ENTITY_TO_CREATE = {
        input: {
          name: 'StixDomainObject',
          type: 'Tool',
          stix_id: stixDomainObjectStixId,
          description: 'StixDomainObject description',
        },
      };
      const stixDomainObject = await queryAsAdminWithSuccess({
        query: CREATE_QUERY,
        variables: STIX_DOMAIN_ENTITY_TO_CREATE,
      });
      const stixDomainObjectInternalId = stixDomainObject?.data?.stixDomainObjectAdd.id;
      const importPushQueryResult = await queryAsAdminWithSuccess({
        query: IMPORT_FILE_QUERY,
        variables: { id: stixDomainObjectInternalId, file: upload, fileMarkings: [MARKING_DEFINITION_TO_CREATE] },
      });

      console.log('---------------stixDomainObject', JSON.stringify(stixDomainObject), '---------------importPushQueryResult', JSON.stringify(importPushQueryResult));
      expect(importPushQueryResult?.data?.stixDomainObjectEdit.importPush.id).toBeDefined();

      // Forth step : verify the marking is on the file
      const READ_QUERY = gql`
        query stixDomainObject($id: String!) {
          stixDomainObject(id: $id) {
            id
            importFiles {
              edges {
                node {
                  id
                  objectMarking {
                    id
                    standard_id
                  }
                }
              }
            }
          }
        }
      `;

      const queryResult = await queryAsAdminWithSuccess({
        query: READ_QUERY,
        variables: { id: stixDomainObjectInternalId },
      });
      const file = queryResult?.data?.stixDomainObject.importFiles.edges[0].node;
      expect(file.objectMarking.length).toBe(1);
      expect(file.objectMarking[0].standard_id).toBe(customMarkingId);

      // Third step : Delete the marking
      const DELETE_MARKING_QUERY = gql`
        mutation markingDefinitionDelete($id: ID!) {
          markingDefinitionEdit(id: $id) {
            delete
          }
        }
      `;

      await queryAsAdminWithSuccess({
        query: DELETE_MARKING_QUERY,
        variables: { id: markingDefinitionInternalId },
      });

      // Forth step : call batchFileMarkingDefinitions to see if the result doesn't have the id of the deleted marking
      const finalQueryResult = await queryAsAdminWithSuccess({
        query: READ_QUERY,
        variables: { id: stixDomainObjectInternalId },
      });
      const fileAfterDeletion = finalQueryResult?.data?.stixDomainObject.importFiles.edges[0].node;

      expect(fileAfterDeletion.objectMarking).toEqual([]);

      // Fifth step : cleanup
      const DELETE_QUERY = gql`
        mutation stixDomainObjectDelete($id: ID!) {
          stixDomainObjectEdit(id: $id) {
            delete
          }
        }
      `;

      await queryAsAdminWithSuccess({
        query: DELETE_QUERY,
        variables: { id: stixDomainObjectInternalId },
      });
    });
  });
});
