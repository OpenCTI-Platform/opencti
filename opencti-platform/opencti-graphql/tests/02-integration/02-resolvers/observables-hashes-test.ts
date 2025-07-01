import { describe, it, expect } from 'vitest';
import gql from 'graphql-tag';
import type { EditInput, StixFileAddInput } from '../../../src/generated/graphql';
import { queryAsAdmin } from '../../utils/testQuery';
import { generateStandardId } from '../../../src/schema/identifier';

const CREATE_STIX_FILE_QUERY = gql`
  mutation CreateStixFile($input: StixFileAddInput) {
    stixCyberObservableAdd(type: "StixFile", StixFile: $input) {
      id
      standard_id
      x_opencti_stix_ids
      ... on StixFile {
        name
        hashes {
            algorithm
            hash
        }
      }
    }
  }
`;

const EDIT_STIX_FILE_QUERY = gql`
  mutation EditStixFile($id: ID!, $input: [EditInput]!) {
    stixCyberObservableEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        standard_id
        x_opencti_stix_ids
        ... on StixFile {
          name
          hashes {
            algorithm
            hash
          }
        }
      }
    }
  }
`;

const FILE1 = {
  name: 'file1',
  md5: '721a9b52bfceacc503c056e3b9b93cfa',
  sha1: 'cb99b709a1978bd205ab9dfd4c5aaa1fc91c7523',
};

const FILE2 = {
  name: 'file2',
  md5: '1c1c96fd2cf8330db0bfa936ce82f3b9',
  sha1: '5ed25af7b1ed23fb00122e13d7f74c4d8262acd8',
};

const FILE3 = {
  name: 'file3',
  md5: '1c1c96fd2cf8330db0bfa936ce82f3b9',
  sha1: 'cb99b709a1978bd205ab9dfd4c5aaa1fc91c7523',
};

describe('Observables with hashes: management of other stix ids', () => {
  it('should replace standard_id and add old one in other_stix_ids if prior data arrives', async () => {
    // Scenario 1 (upsert)
    // -------------------
    // Create StixFile1 with only name (standard_id based on name) (other_stix_ids empty).
    const file1WithNameInput: StixFileAddInput = {
      name: FILE1.name,
    };
    const file1WithNameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameInput },
    });
    const file1WithName = file1WithNameResult?.data?.stixCyberObservableAdd;
    const file1WithNameStandardId = generateStandardId('StixFile', file1WithNameInput);
    expect(file1WithName.standard_id).toEqual(file1WithNameStandardId);
    expect(file1WithName.x_opencti_stix_ids).toEqual([]);
    // UPSERT StixFile1 with name and SHA1 (standard_id based on SHA1) (other_stix_ids has standard_name).
    const file1WithNameSha1Input: StixFileAddInput = {
      name: FILE1.name,
      hashes: [
        { algorithm: 'SHA-1', hash: FILE1.sha1 }
      ]
    };
    const file1WithNameSha1Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameSha1Input },
    });
    const file1WithNameSha1 = file1WithNameSha1Result?.data?.stixCyberObservableAdd;
    const file1WithNameSha1StandardId = generateStandardId('StixFile', file1WithNameSha1Input);
    expect(file1WithNameSha1.id).toEqual(file1WithName.id);
    expect(file1WithNameSha1.standard_id).toEqual(file1WithNameSha1StandardId);
    expect(file1WithNameSha1.x_opencti_stix_ids).toEqual([file1WithName.standard_id]);
    // UPSERT StixFile1 with name, SHA1 and MD5 (standard_id based on MD5) (other_stix_ids has standard_name, standard_SHA1).
    const file1WithNameSha1Md5Input: StixFileAddInput = {
      name: FILE1.name,
      hashes: [
        { algorithm: 'SHA-1', hash: FILE1.sha1 },
        { algorithm: 'MD5', hash: FILE1.md5 }
      ]
    };
    const file1WithNameSha1Md5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameSha1Md5Input },
    });
    const file1WithNameSha1Md5 = file1WithNameSha1Md5Result?.data?.stixCyberObservableAdd;
    const file1WithNameSha1Md5StandardId = generateStandardId('StixFile', file1WithNameSha1Md5Input);
    expect(file1WithNameSha1Md5.id).toEqual(file1WithName.id);
    expect(file1WithNameSha1Md5.standard_id).toEqual(file1WithNameSha1Md5StandardId);
    expect(file1WithNameSha1Md5.x_opencti_stix_ids).toEqual([file1WithName.standard_id, file1WithNameSha1.standard_id]);

    // Scenario 2 (update)
    // -------------------
    // Create StixFile2 with only name (standard_id based on name) (other_stix_ids empty).
    const file2WithNameInput: StixFileAddInput = {
      name: FILE2.name,
    };
    const file2WithNameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file2WithNameInput },
    });
    const file2WithName = file2WithNameResult?.data?.stixCyberObservableAdd;
    const file2WithNameStandardId = generateStandardId('StixFile', file2WithNameInput);
    expect(file2WithName.standard_id).toEqual(file2WithNameStandardId);
    expect(file2WithName.x_opencti_stix_ids).toEqual([]);
    // UPDATE StixFile2 with SHA1 (standard_id based on SHA1) (other_stix_ids has standard_name).
    const file2WithNameSha1Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-1',
      value: [FILE2.sha1]
    }];
    const file2WithNameSha1Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2WithName.id,
        input: file2WithNameSha1Input,
      },
    });
    const file2WithNameSha1 = file2WithNameSha1Result?.data?.stixCyberObservableEdit;
    const file2WithNameSha1StandardId = generateStandardId('StixFile', {
      name: FILE2.name,
      hashes: [
        { algorithm: 'SHA-1', hash: FILE2.sha1 }
      ]
    });
    expect(file2WithNameSha1.standard_id).toEqual(file2WithNameSha1StandardId);
    expect(file2WithNameSha1.x_opencti_stix_ids).toEqual([file2WithName.standard_id]);
    // UPDATE StixFile2 with name, SHA1 and MD5 (standard_id based on MD5) (other_stix_ids has standard_name, standard_SHA1).
    const file2WithNameSha1Md5Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/MD5',
      value: [FILE2.md5]
    }];
    const file2WithNameSha1Md5Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2WithName.id,
        input: file2WithNameSha1Md5Input,
      },
    });
    const file2WithNameSha1Md5 = file2WithNameSha1Md5Result?.data?.stixCyberObservableEdit;
    const file2WithNameSha1Md5StandardId = generateStandardId('StixFile', {
      name: FILE2.name,
      hashes: [
        { algorithm: 'SHA-1', hash: FILE2.sha1 },
        { algorithm: 'MD5', hash: FILE2.md5 }
      ]
    });
    expect(file2WithNameSha1Md5.standard_id).toEqual(file2WithNameSha1Md5StandardId);
    expect(file2WithNameSha1Md5.x_opencti_stix_ids).toEqual([file2WithName.standard_id, file2WithNameSha1.standard_id]);
  });

  it('should not replace standard_id if less prior data arrives but still add its standard_id in other_stix_ids', async () => {
    // Scenario 1 (upsert)
    // -------------------
    // Create StixFile3 with only MD5 (standard_id based on MD5) (other_stix_ids empty).
    const file3WithMD5Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'MD5', hash: FILE3.md5 },
      ]
    };
    const file3WithMD5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file3WithMD5Input },
    });
    const file3WithMd5 = file3WithMD5Result.data?.stixCyberObservableAdd;
    const file3WithMd5StandardId = generateStandardId('StixFile', file3WithMD5Input);
    expect(file3WithMd5.standard_id).toEqual(file3WithMd5StandardId);
    expect(file3WithMd5.x_opencti_stix_ids).toEqual([]);
    // UPSERT StixFile3 with MD5 and SHA1 (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    const fileWithMd5Sha1Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'MD5', hash: FILE3.md5 },
        { algorithm: 'SHA-1', hash: FILE3.sha1 },
      ]
    };
    const file3WithMd5Sha1Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: fileWithMd5Sha1Input }
    });
    const file3WithMd5Sha1 = file3WithMd5Sha1Result.data?.stixCyberObservableAdd;
    const file3WithMd5Sha1StandardId = generateStandardId('StixFile', fileWithMd5Sha1Input);
    expect(file3WithMd5Sha1.id).equal(file3WithMd5);
    expect(file3WithMd5.standard_id).toEqual(file3WithMd5Sha1StandardId);
    expect(file3WithMd5Sha1.x_opencti_stix_ids).toEqual([file3WithMd5.standard_id]);
    // UPSERT StixFile3 with MD5, SHA1 and name (standard_id based on MD5) (other_stix_ids has standard_SHA1, standard_name).
    const file3WithMd5Sha1NameInput: StixFileAddInput = {
      name: FILE3.name,
      hashes: [
        { algorithm: 'MD5', hash: FILE3.md5 },
        { algorithm: 'SHA-1', hash: FILE3.sha1 },
      ]
    };
    const file3WithSha1Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'SHA-1', hash: FILE3.sha1 },
      ]
    };
    const file3WitNameInput: StixFileAddInput = {
      name: FILE3.name,
    };
    const file3Md5Sha1NameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file3WithMd5Sha1NameInput },
    });
    const file3WithMd5Sha1Name = file3Md5Sha1NameResult?.data?.stixCyberObservableAdd;
    const file3WithMd5Sha1NameStandardId = generateStandardId('StixFile', file3WithMd5Sha1NameInput);
    const file3WithSha1StandardId = generateStandardId('StixFile', file3WithSha1Input);
    const file3WithNameStandardId = generateStandardId('StixFile', file3WitNameInput);
    expect(file3WithMd5Sha1Name.id).toEqual(file3WithMd5.id);
    expect(file3WithMd5Sha1Name.standard_id).toEqual(file3WithMd5Sha1NameStandardId);
    expect(file3WithMd5Sha1Name.x_opencti_stix_ids).toEqual([file3WithSha1StandardId, file3WithNameStandardId]);

    // Scenario 2 (update)
    // -------------------
    // Create StixFile4 with only MD5 (standard_id based on MD5) (other_stix_ids empty).
    // UPDATE StixFile4 with MD5 and SHA1 (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPDATE StixFile4 with MD5, SHA1 and name (standard_id based on MD5) (other_stix_ids has standard_SHA1, standard_name).
  });

  it('should merge observables and other_stix_ids', () => {
    // Create StixFile5 with only name (standard_id based on name) (other_stix_ids empty).
    // Create StixFile6 with MD5 (standard_id based on MD5) (other_stix_ids empty).
    // Create StixFile7 with MD5 and name => Merge (standard_id based on MD5) (other_stix_ids has standard_name).
  });

  it('should clean standard from other_stix_ids if correlated data is removed', () => {
    // Scenario 1 (no change of standard_id)
    // -------------------------------------
    // UPDATE StixFile4 to remove name (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPDATE StixFile4 to remove SHA1 (standard_id based on MD5) (other_stix_ids empty).

    // Scenario 2 (standard_id changes)
    // --------------------------------
    // UPDATE StixFile3 to remove name (standard_id based on MD5) (other_stix_ids has standard_SHA1).
    // UPDATE StixFile3 to remove MD5 (standard_id based on SHA1) (other_stix_ids empty).
    // UPDATE StixFile2 to remove MD5 (standard_id based on SHA1) (other_stix_ids has standard_name).
    // UPDATE StixFile2 to remove SHA1 (standard_id based on name) (other_stix_ids empty).
  });
});
