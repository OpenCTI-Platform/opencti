import { describe, it, expect, beforeAll } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { downloadFile, streamConverter } from '../../../src/database/file-storage';
import { fileToReadStream } from '../../../src/database/file-storage-helper';
import { elLoadById } from '../../../src/database/engine';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR } from '../../../src/schema/stixCyberObservable';

const CREATE_CONTENT_MUTATION = gql`
  mutation exclusionListContentAdd($input: ExclusionListContentAddInput!) {
    exclusionListContentAdd(input: $input) {
      id
      file_id
      exclusion_list_entity_types
      exclusion_list_values_count
      exclusion_list_file_size
    }
  }
`;

const CREATE_FILE_MUTATION = gql`
  mutation exclusionListFileAdd($input: ExclusionListFileAddInput!) {
    exclusionListFileAdd(input: $input) {
      id
      file_id
      exclusion_list_entity_types
      exclusion_list_values_count
      exclusion_list_file_size
    }
  }
`;

const FIELD_PATCH_MUTATION = gql`
  mutation exclusionListFileUpdate($id: ID!, $input: [EditInput!], $file: Upload) {
    exclusionListFieldPatch(id: $id, input: $input, file: $file) {
      id
      file_id
      exclusion_list_entity_types
      exclusion_list_values_count
      exclusion_list_file_size
    }
  }
`;

const DELETE_MUTATION = gql`
  mutation exclusionListDelete($id: ID!) {
    exclusionListDelete(id: $id)
  }
`;

const LIST_QUERY = gql`
  query exclusionLists(
    $first: Int
    $after: ID
    $orderBy: ExclusionListOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    exclusionLists(
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
          exclusion_list_entity_types
        }
      }
    }
  }
`;

type ExclusionListResponse = {
  id: string | null;
  file_id: string | null;
  exclusion_list_values_count: number | null;
  exclusion_list_file_size: number | null;
};

const createUploadFile = (filePath: string, fileName: string) => {
  const readStream = fileToReadStream(filePath, fileName, fileName, 'text/plain');
  const fileUpload = { ...readStream, encoding: 'utf8' };
  const upload = new Upload();
  upload.promise = new Promise((executor) => {
    executor(fileUpload);
  });
  upload.file = fileUpload;

  return upload;
};

describe('Exclusion list resolver', () => {
  let exclusionListResponse: ExclusionListResponse = { id: null, file_id: null, exclusion_list_values_count: null, exclusion_list_file_size: null };
  let exclusionListFileResponse: ExclusionListResponse = { id: null, file_id: null, exclusion_list_values_count: null, exclusion_list_file_size: null };

  describe('exclusionListValuesAdd', () => {
    describe('If I create an exclusion with a content', () => {
      beforeAll(async () => {
        const result = await queryAsAdminWithSuccess({
          query: CREATE_CONTENT_MUTATION,
          variables: {
            input: {
              name: 'test_name',
              description: 'test_description',
              exclusion_list_entity_types: ENTITY_DOMAIN_NAME,
              content: 'test_content.fr'
            }
          }
        });
        exclusionListResponse = result?.data?.exclusionListContentAdd as ExclusionListResponse;
      });

      it('should create an exclusion list', async () => {
        expect(exclusionListResponse.id).toBeDefined();
        expect(exclusionListResponse.file_id).toBe(`exclusionLists/${exclusionListResponse.id}.txt`);
        expect(exclusionListResponse.exclusion_list_values_count).toBe(1);
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
        const upload = createUploadFile('./tests/data/exclusionLists/', 'testFileExclusionList.txt');

        const result = await queryAsAdminWithSuccess({
          query: CREATE_FILE_MUTATION,
          variables: {
            input: {
              name: 'test_name_file',
              description: 'test_description_file',
              exclusion_list_entity_types: ENTITY_IPV4_ADDR,
              file: upload,
            }
          }
        });
        exclusionListFileResponse = result?.data?.exclusionListFileAdd as ExclusionListResponse;
      });

      it('should create an exclusion list', async () => {
        expect(exclusionListFileResponse.id).toBeDefined();
        expect(exclusionListFileResponse.file_id).toBe(`exclusionLists/${exclusionListFileResponse.id}.txt`);
        expect(exclusionListFileResponse.exclusion_list_values_count).toBe(3);
        expect(exclusionListFileResponse.exclusion_list_file_size).toBe(27);
      });

      it('should create a file', async () => {
        const fileStream = await downloadFile(exclusionListFileResponse.file_id);
        expect(fileStream).not.toBeNull();
        const data = await streamConverter(fileStream);
        expect(data).toEqual('127.0.0.1\n10.10.0.0\n2.2.2.2');
      });

      it('should update exclusion list file', async () => {
        // Update file of exclusion list
        const upload = createUploadFile('./tests/data/exclusionLists/', 'testFileExclusionListUpdate.txt');
        const fieldPatch = await queryAsAdminWithSuccess({
          query: FIELD_PATCH_MUTATION,
          variables: {
            id: exclusionListFileResponse.id,
            file: upload
          }
        });
        expect(fieldPatch?.data?.exclusionListFieldPatch.exclusion_list_values_count).toBe(4);
        expect(fieldPatch?.data?.exclusionListFieldPatch.exclusion_list_file_size).toBe(37);
        // verify that file was modified
        const fileStream = await downloadFile(exclusionListFileResponse.file_id);
        expect(fileStream).not.toBeNull();
        const data = await streamConverter(fileStream);
        expect(data).toEqual('127.0.0.1\n10.10.0.0\n12.10.0.0\n2.2.2.2');
      });

      it('should list exclusion lists', async () => {
        const listResult = await queryAsAdminWithSuccess({
          query: LIST_QUERY,
          variables: { first: 5 },
        });
        const exclusionLists = listResult.data?.exclusionLists.edges;
        expect(exclusionLists).toBeDefined();
        expect(exclusionLists.length).toEqual(2);

        const filters = {
          mode: 'and',
          filters: [{
            key: 'exclusion_list_entity_types',
            operator: 'eq',
            values: [ENTITY_IPV4_ADDR],
            mode: 'or',
          }],
          filterGroups: [],
        };
        const listWithFilterResult = await queryAsAdminWithSuccess({
          query: LIST_QUERY,
          variables: { first: 5, filters },
        });
        const exclusionListsWithFilter = listWithFilterResult.data?.exclusionLists.edges;
        expect(exclusionListsWithFilter).toBeDefined();
        expect(exclusionListsWithFilter.length).toEqual(1);
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
