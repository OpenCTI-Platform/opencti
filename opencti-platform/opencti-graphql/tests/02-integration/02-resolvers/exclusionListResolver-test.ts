import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { downloadFile, streamConverter } from '../../../src/database/file-storage';
import { fileToReadStream } from '../../../src/database/file-storage-helper';
import { elLoadById } from '../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ExclusionListEntityTypes } from '../../../src/generated/graphql';

const CREATE_CONTENT_MUTATION = gql`
  mutation exclusionListContentAdd($input: ExclusionListContentAddInput!) {
    exclusionListContentAdd(input: $input) {
      id
      file_id
    }
  }
`;

const CREATE_FILE_MUTATION = gql`
  mutation exclusionListFileAdd($input: ExclusionListFileAddInput!) {
    exclusionListFileAdd(input: $input) {
      id
      file_id
    }
  }
`;

const DELETE_MUTATION = gql`
  mutation exclusionListDelete($id: ID!) {
    exclusionListDelete(id: $id)
  }
`;

type ExclusionListResponse = {
  id: string | null;
  file_id: string | null;
};

describe('Exclusion list resolver', () => {
  let exclusionListResponse: ExclusionListResponse = { id: null, file_id: null };
  let exclusionListFileResponse: ExclusionListResponse = { id: null, file_id: null };

  describe('exclusionListValuesAdd', () => {
    describe('If I create an exclusion with a content', () => {
      beforeAll(async () => {
        const result = await queryAsAdminWithSuccess({
          query: CREATE_CONTENT_MUTATION,
          variables: {
            input: {
              name: 'test_name',
              description: 'test_description',
              list_entity_types: [ExclusionListEntityTypes.DomainName],
              content: 'test_content.fr'
            }
          }
        });
        exclusionListResponse = result?.data?.exclusionListContentAdd as ExclusionListResponse;
      });

      it('should create an exclusion list', async () => {
        expect(exclusionListResponse.id).toBeDefined();
        expect(exclusionListResponse.file_id).toBe('exclusionLists/test_name.txt');
      });

      it('should create a file', async () => {
        const fileStream = await downloadFile(exclusionListResponse.file_id);
        expect(fileStream).not.toBeNull();
        const data = await streamConverter(fileStream);
        expect(data).toBe('test_content.fr');
      });
    });
  });

  describe('addExclusionListFile', () => {
    describe('If I create an exclusion with a file', () => {
      beforeAll(async () => {
        const readStream = fileToReadStream('./tests/data/exclusionLists/', 'testFileExclusionList.txt', 'testFileExclusionList.txt', 'text/plain');
        const fileUpload = { ...readStream, encoding: 'utf8' };
        const upload = new Upload();
        upload.promise = new Promise((executor) => {
          executor(fileUpload);
        });
        upload.file = fileUpload;

        const result = await queryAsAdminWithSuccess({
          query: CREATE_FILE_MUTATION,
          variables: {
            input: {
              name: 'test_name_file',
              description: 'test_description_file',
              list_entity_types: [ExclusionListEntityTypes.Ipv4Addr],
              file: upload,
            }
          }
        });
        exclusionListFileResponse = result?.data?.exclusionListFileAdd as ExclusionListResponse;
      });

      it('should create an exclusion list', async () => {
        expect(exclusionListFileResponse.id).toBeDefined();
        expect(exclusionListFileResponse.file_id).toBe('exclusionLists/testfileexclusionlist.txt');
      });

      it('should create a file', async () => {
        const fileStream = await downloadFile(exclusionListFileResponse.file_id);
        expect(fileStream).not.toBeNull();
        const data = await streamConverter(fileStream);
        expect(data).toEqual('127.0.0.1\n10.10.0.0\n2.2.2.2');
      });
    });
  });

  describe('exclusionListDelete', () => {
    describe('If I delete an exclusion list from a content creation', () => {
      beforeAll(async () => {
        await queryAsAdminWithSuccess({
          query: DELETE_MUTATION,
          variables: {
            id: exclusionListResponse?.id
          }
        });
      });

      it('should have deleted the elastic object', async () => {
        const exclusionList = await elLoadById(testContext, ADMIN_USER, exclusionListResponse?.id);
        expect(exclusionList).not.toBeDefined();
      });

      it('should have deleted the file', async () => {
        const fileStream = await downloadFile(exclusionListResponse?.file_id);
        expect(fileStream).toBeNull();
      });
    });

    describe('If I delete an exclusion list from a file creation', () => {
      beforeAll(async () => {
        await queryAsAdminWithSuccess({
          query: DELETE_MUTATION,
          variables: {
            id: exclusionListFileResponse?.id
          }
        });
      });

      it('should have deleted the elastic object', async () => {
        const exclusionList = await elLoadById(testContext, ADMIN_USER, exclusionListFileResponse?.id);
        expect(exclusionList).not.toBeDefined();
      });

      it('should have deleted the file', async () => {
        const fileStream = await downloadFile(exclusionListFileResponse?.file_id);
        expect(fileStream).toBeNull();
      });
    });
  });
});
