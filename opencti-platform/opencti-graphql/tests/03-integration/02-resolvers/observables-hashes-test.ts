import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { type EditInput, EditOperation, type StixFileAddInput } from '../../../src/generated/graphql';
import { queryAsAdmin } from '../../utils/testQuery';
import { generateStandardId } from '../../../src/schema/identifier';
import { IDS_STIX } from '../../../src/schema/general';

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

const DELETE_STIX_FILE_QUERY = gql`
  mutation DeleteStixFile($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
    }
  }
`;

const FIND_BY_ID_QUERY = gql`
  query FindStixFile($id: String!) {
    stixCyberObservable(id: $id) {
      standard_id
    }
  }
`;

const FILE1 = {
  name: 'file1',
  md5: '826e8142e6baabe8af779f5f490cf5f5',
  sha1: '60b27f004e454aca81b0480209cce5081ec52390',
  sha256: 'c147efcfc2d7ea666a9e4f5187b115c90903f0fc896a56df9a6ef5d8f3fc9f31'
};

const FILE2 = {
  name: 'file2',
  md5: '1c1c96fd2cf8330db0bfa936ce82f3b9',
  sha1: 'cb99b709a1978bd205ab9dfd4c5aaa1fc91c7523',
  sha256: '3377870dfeaaa7adf79a374d2702a3fdb13e5e5ea0dd8aa95a802ad39044a92f'
};

const FILE3 = {
  name: 'file3',
  md5: '2548729e9c3c60cc3789dfb2408e475d',
  sha1: 'd5b0a58bc47161b1b8a831084b366f757c4f0b11',
  sha256: '6f3fef6dc51c7996a74992b70d0c35f328ed909a5e07646cf0bab3383c95bb02'
};

const FILE4 = {
  name: 'file4',
  md5: '33e28153f08dcd28a4c4292ad4c866af',
  sha1: '1b641bf4f6b84efcd42920ff1a88ff2f97fb9d08',
  sha256: '600456c60420b0c6ddfe3b8d50cb6e63af544fb26c5715ae58a601bcca9a055d'
};

const FILE5 = {
  name: 'file5',
  md5: '025ad219ece1125a8f5a0e74e32676cb',
  sha1: 'c1750bee9c1f7b5dd6f025b645ab6eba5df94175',
  sha256: '9a8363aff25b5ffb5120eeb66d735bfd225d6e27d0a1ce6afc2a6b177bb94336'
};

describe('Observables with hashes: management of other stix ids', () => {
  let file1Id: string;
  const file1StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE1.sha1 } });
  const file1StandardIdBySha256 = generateStandardId('StixFile', { hashes: { 'SHA-256': FILE1.sha256 } });
  const file1StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE1.md5 } });

  let file2Id: string;
  const file2StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE2.sha1 } });
  const file2StandardIdBySha256 = generateStandardId('StixFile', { hashes: { 'SHA-256': FILE2.sha256 } });
  const file2StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE2.md5 } });

  let file3Id: string;
  const file3StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE3.sha1 } });
  const file3StandardIdBySha256 = generateStandardId('StixFile', { hashes: { 'SHA-256': FILE3.sha256 } });
  const file3StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE3.md5 } });

  let file4Id: string;
  let file4StixIds: string[];
  const file4StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE4.sha1 } });
  const file4StandardIdBySha256 = generateStandardId('StixFile', { hashes: { 'SHA-256': FILE4.sha256 } });
  const file4StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE4.md5 } });

  let file5Id: string;
  const file5StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE5.sha1 } });
  const file5StandardIdBySha256 = generateStandardId('StixFile', { hashes: { 'SHA-256': FILE5.sha256 } });
  const file5StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE5.md5 } });

  afterAll(async () => {
    await queryAsAdmin({
      query: DELETE_STIX_FILE_QUERY,
      variables: { id: file1Id, },
    });
    await queryAsAdmin({
      query: DELETE_STIX_FILE_QUERY,
      variables: { id: file2Id, },
    });
    await queryAsAdmin({
      query: DELETE_STIX_FILE_QUERY,
      variables: { id: file3Id, },
    });
    await queryAsAdmin({
      query: DELETE_STIX_FILE_QUERY,
      variables: { id: file4Id, },
    });
    await queryAsAdmin({
      query: DELETE_STIX_FILE_QUERY,
      variables: { id: file5Id, },
    });
  });

  it('should replace standard_id and add old one in x_opencti_stix_ids if prior data arrives by Upsert', async () => {
    // Create StixFile1 with only name (standard_id based on name) (x_opencti_stix_ids empty).
    const file1WithNameSha256Input: StixFileAddInput = {
      name: FILE1.name,
      hashes: [
        { algorithm: 'SHA-256', hash: FILE1.sha256 }
      ]
    };
    const file1WithNameSha256Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameSha256Input },
    });
    const file1WithNameSha256 = file1WithNameSha256Result?.data?.stixCyberObservableAdd;
    file1Id = file1WithNameSha256?.id;
    expect(file1WithNameSha256?.standard_id).toEqual(file1StandardIdBySha256);
    expect(file1WithNameSha256?.x_opencti_stix_ids).toEqual([]);
    // UPSERT StixFile1 with name and SHA1 (standard_id based on SHA1) (x_opencti_stix_ids has standard_sha256).
    const file1WithNameSha256Sha1Input: StixFileAddInput = {
      name: FILE1.name,
      hashes: [
        { algorithm: 'SHA-256', hash: FILE1.sha256 },
        { algorithm: 'SHA-1', hash: FILE1.sha1 }
      ]
    };
    const file1WithNameSha256Sha1Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameSha256Sha1Input },
    });
    const file1WithNameSha256Sha1 = file1WithNameSha256Sha1Result?.data?.stixCyberObservableAdd;
    expect(file1WithNameSha256Sha1?.id).toEqual(file1Id);
    expect(file1WithNameSha256Sha1?.standard_id).toEqual(file1StandardIdBySha1);
    expect(file1WithNameSha256Sha1?.x_opencti_stix_ids).toEqual([file1StandardIdBySha256]);
    // UPSERT StixFile1 with name, SHA1 and MD5 (standard_id based on MD5) (x_opencti_stix_ids has standard_sha256, standard_SHA1).
    const file1WithNameSha256Md5Input: StixFileAddInput = {
      name: FILE1.name,
      hashes: [
        { algorithm: 'SHA-256', hash: FILE1.sha256 },
        { algorithm: 'MD5', hash: FILE1.md5 }
      ]
    };
    const file1WithNameSha256Md5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameSha256Md5Input },
    });
    const file1WithNameSha256Md5 = file1WithNameSha256Md5Result?.data?.stixCyberObservableAdd;
    expect(file1WithNameSha256Md5?.id).toEqual(file1Id);
    expect(file1WithNameSha256Md5?.standard_id).toEqual(file1StandardIdByMd5);
    expect(file1WithNameSha256Md5?.x_opencti_stix_ids).toEqual([file1StandardIdBySha256, file1StandardIdBySha1]);
    // Verify there is only one file in elastic
    const fileBySha1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file1StandardIdBySha1 },
    });
    expect(fileBySha1?.data?.stixCyberObservable.standard_id).toEqual(file1StandardIdByMd5);
    const fileBySha256 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file1StandardIdBySha256 },
    });
    expect(fileBySha256?.data?.stixCyberObservable.standard_id).toEqual(file1StandardIdByMd5);
  });

  it('should replace standard_id and add old one in x_opencti_stix_ids if prior data arrives by Update', async () => {
    // Create StixFile2 with only name (standard_id based on name) (x_opencti_stix_ids empty).
    const file2WithNameSha256Input: StixFileAddInput = {
      name: FILE2.name,
      hashes: [
        { algorithm: 'SHA-256', hash: FILE2.sha256 }
      ]
    };
    const file2WithNameSha256Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file2WithNameSha256Input },
    });
    const file2WithNameSha256 = file2WithNameSha256Result?.data?.stixCyberObservableAdd;
    file2Id = file2WithNameSha256?.id;
    expect(file2WithNameSha256?.standard_id).toEqual(file2StandardIdBySha256);
    expect(file2WithNameSha256?.x_opencti_stix_ids).toEqual([]);
    // UPDATE StixFile2 with SHA1 (standard_id based on SHA1) (x_opencti_stix_ids has standard_sha256).
    const file2WithNameSha256Sha1Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-1',
      value: [FILE2.sha1]
    }];
    const file2WithNameSha256Sha1Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2Id,
        input: file2WithNameSha256Sha1Input,
      },
    });
    const file2WithNameSha256Sha1 = file2WithNameSha256Sha1Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file2WithNameSha256Sha1?.standard_id).toEqual(file2StandardIdBySha1);
    expect(file2WithNameSha256Sha1?.x_opencti_stix_ids).toEqual([file2StandardIdBySha256]);
    // UPDATE StixFile2 with name, SHA1 and MD5 (standard_id based on MD5) (x_opencti_stix_ids has standard_sha256, standard_SHA1).
    const file2WithNameSha256Sha1Md5Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/MD5',
      value: [FILE2.md5]
    }];
    const file2WithNameSha256Sha1Md5Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2Id,
        input: file2WithNameSha256Sha1Md5Input,
      },
    });
    const file2WithNameSha256Sha1Md5 = file2WithNameSha256Sha1Md5Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file2WithNameSha256Sha1Md5?.standard_id).toEqual(file2StandardIdByMd5);
    expect(file2WithNameSha256Sha1Md5?.x_opencti_stix_ids).toEqual([file2StandardIdBySha1, file2StandardIdBySha256]);
    // Verify there is only one file in elastic
    const fileBySha1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file2StandardIdBySha1 },
    });
    expect(fileBySha1?.data?.stixCyberObservable.standard_id).toEqual(file2StandardIdByMd5);
    const fileBySha256 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file2StandardIdBySha256 },
    });
    expect(fileBySha256?.data?.stixCyberObservable.standard_id).toEqual(file2StandardIdByMd5);
  });

  it('should not replace standard_id if less prior data arrives but still add its standard_id in x_opencti_stix_ids by Upsert', async () => {
    // Create StixFile3 with only MD5 (standard_id based on MD5) (x_opencti_stix_ids empty).
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
    file3Id = file3WithMd5?.id;
    expect(file3WithMd5?.standard_id).toEqual(file3StandardIdByMd5);
    expect(file3WithMd5?.x_opencti_stix_ids).toEqual([]);
    // UPSERT StixFile3 with MD5 and SHA1 (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
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
    expect(file3WithMd5Sha1?.id).equal(file3Id);
    expect(file3WithMd5Sha1?.standard_id).toEqual(file3StandardIdByMd5);
    expect(file3WithMd5Sha1?.x_opencti_stix_ids).toEqual([file3StandardIdBySha1]);
    // UPSERT StixFile3 with MD5, SHA1 and name (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file3WithMd5Sha1NameInput: StixFileAddInput = {
      name: FILE3.name,
      hashes: [
        { algorithm: 'MD5', hash: FILE3.md5 },
        { algorithm: 'SHA-1', hash: FILE3.sha1 },
      ]
    };
    const file3Md5Sha1NameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file3WithMd5Sha1NameInput },
    });
    const file3WithMd5Sha1Name = file3Md5Sha1NameResult?.data?.stixCyberObservableAdd;
    expect(file3WithMd5Sha1Name?.id).toEqual(file3Id);
    expect(file3WithMd5Sha1Name?.standard_id).toEqual(file3StandardIdByMd5);
    expect(file3WithMd5Sha1Name?.x_opencti_stix_ids).toEqual([file3StandardIdBySha1]);
    // UPSERT StixFile3 with MD5, SHA1, name and SHA26 (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1, standard_sha256).
    const file3WithMd5Sha1NameSha256Input: StixFileAddInput = {
      name: FILE3.name,
      hashes: [
        { algorithm: 'MD5', hash: FILE3.md5 },
        { algorithm: 'SHA-1', hash: FILE3.sha1 },
        { algorithm: 'SHA-256', hash: FILE3.sha256 },
      ]
    };
    const file3Md5Sha1NameSha256Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file3WithMd5Sha1NameSha256Input },
    });
    const file3WithMd5Sha1NameSha256 = file3Md5Sha1NameSha256Result?.data?.stixCyberObservableAdd;
    expect(file3WithMd5Sha1NameSha256?.id).toEqual(file3Id);
    expect(file3WithMd5Sha1NameSha256?.standard_id).toEqual(file3StandardIdByMd5);
    expect(file3WithMd5Sha1NameSha256?.x_opencti_stix_ids).toEqual([file3StandardIdBySha1, file3StandardIdBySha256]);
    // Verify there is only one file in elastic
    const fileBySha1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file3StandardIdBySha1 },
    });
    expect(fileBySha1?.data?.stixCyberObservable.standard_id).toEqual(file3StandardIdByMd5);
    const fileBySha256 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file3StandardIdBySha256 },
    });
    expect(fileBySha256?.data?.stixCyberObservable.standard_id).toEqual(file3StandardIdByMd5);
  });

  it('should not replace standard_id if less prior data arrives but still add its standard_id in x_opencti_stix_ids by Update', async () => {
    // Create StixFile4 with only MD5 (standard_id based on MD5) (x_opencti_stix_ids empty).
    const file4WithMd5Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'MD5', hash: FILE4.md5 },
      ]
    };
    const file4WithMd5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file4WithMd5Input },
    });
    const file4WithMd5 = file4WithMd5Result?.data?.stixCyberObservableAdd;
    file4Id = file4WithMd5?.id;
    expect(file4WithMd5?.standard_id).toEqual(file4StandardIdByMd5);
    expect(file4WithMd5?.x_opencti_stix_ids).toEqual([]);
    // UPDATE StixFile4 with MD5 and SHA1 (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file4WithMd5Sha1Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-1',
      value: [FILE4.sha1]
    }];
    const file4WithMd5Sha1Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file4Id,
        input: file4WithMd5Sha1Input,
      }
    });
    const file4WithMd5Sha1 = file4WithMd5Sha1Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file4WithMd5Sha1?.standard_id).toEqual(file4StandardIdByMd5);
    expect(file4WithMd5Sha1?.x_opencti_stix_ids).toEqual([file4StandardIdBySha1]);
    // UPDATE StixFile4 with MD5, SHA1 and name (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file4WithMd5Sha1NameInput: EditInput[] = [{
      key: 'name',
      value: [FILE4.name]
    }];
    const file4WithMd5Sha1NameResult = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file4Id,
        input: file4WithMd5Sha1NameInput,
      }
    });
    const file4WithMd5Sha1Name = file4WithMd5Sha1NameResult.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file4WithMd5Sha1Name?.standard_id).toEqual(file4StandardIdByMd5);
    expect(file4WithMd5Sha1Name?.x_opencti_stix_ids).toEqual([file4StandardIdBySha1]);
    // UPDATE StixFile4 with MD5, SHA1, name and SHA256 (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1 and standard_SHA256).
    const file4WithMd5Sha1NameSha256Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-256',
      value: [FILE4.sha256]
    }];
    const file4WithMd5Sha1NameSha256Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file4Id,
        input: file4WithMd5Sha1NameSha256Input,
      }
    });
    const file4WithMd5Sha1NameSha256 = file4WithMd5Sha1NameSha256Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file4WithMd5Sha1NameSha256?.standard_id).toEqual(file4StandardIdByMd5);
    expect(file4WithMd5Sha1NameSha256?.x_opencti_stix_ids).toEqual([file4StandardIdBySha1, file4StandardIdBySha256]);
    file4StixIds = [file4StandardIdBySha1, file4StandardIdBySha256];
    // Verify there is only one file in elastic
    const fileBySha1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file4StandardIdBySha1 },
    });
    expect(fileBySha1?.data?.stixCyberObservable.standard_id).toEqual(file4StandardIdByMd5);
    const fileBySha256 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file4StandardIdBySha256 },
    });
    expect(fileBySha256?.data?.stixCyberObservable.standard_id).toEqual(file4StandardIdByMd5);
  });

  it('should merge observables and x_opencti_stix_ids', async () => {
    // Create StixFile5 with name and SHA1 (standard_id based on SHA1) (x_opencti_stix_ids empty).
    const file5WithNameSha1Input: StixFileAddInput = {
      name: FILE5.name,
      hashes: [
        { algorithm: 'SHA-1', hash: FILE5.sha1 }
      ]
    };
    const file5WithNameSha1Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file5WithNameSha1Input },
    });
    const file5WithNameSha1 = file5WithNameSha1Result?.data?.stixCyberObservableAdd;
    expect(file5WithNameSha1?.standard_id).toEqual(file5StandardIdBySha1);
    expect(file5WithNameSha1?.x_opencti_stix_ids).toEqual([]);
    // Create StixFile6 with MD5 (standard_id based on MD5) (x_opencti_stix_ids has standard_sha256).
    const file5WithMd5Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'SHA-256', hash: FILE5.sha256 },
        { algorithm: 'MD5', hash: FILE5.md5 }
      ]
    };
    const file5WithMd5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file5WithMd5Input },
    });
    const file5WithMd5 = file5WithMd5Result?.data?.stixCyberObservableAdd;
    file5Id = file5WithMd5?.id;
    expect(file5WithMd5?.id).not.toEqual(file5WithNameSha1?.id);
    expect(file5WithMd5?.standard_id).toEqual(file5StandardIdByMd5);
    expect(file5WithMd5?.x_opencti_stix_ids).toEqual([file5StandardIdBySha256]);
    // Create StixFile7 with MD5 and name => Merge (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file5WithSha1Md5Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'SHA-1', hash: FILE5.sha1 },
        { algorithm: 'MD5', hash: FILE5.md5 }
      ]
    };
    const file5WithSha1Md5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file5WithSha1Md5Input },
    });
    const file5WithSha1Md5 = file5WithSha1Md5Result?.data?.stixCyberObservableAdd;
    expect(file5WithSha1Md5?.id).toEqual(file5Id);
    expect(file5WithSha1Md5?.standard_id).toEqual(file5StandardIdByMd5);
    expect(file5WithSha1Md5?.x_opencti_stix_ids).toEqual([file5StandardIdBySha256, file5StandardIdBySha1]);
    expect(file5WithSha1Md5?.hashes.length).toEqual(3);
    // Verify there is only one file in elastic
    const fileBySha1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file5StandardIdBySha1 },
    });
    expect(fileBySha1?.data?.stixCyberObservable.standard_id).toEqual(file5StandardIdByMd5);
    const fileBySha256 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file5StandardIdBySha256 },
    });
    expect(fileBySha256?.data?.stixCyberObservable.standard_id).toEqual(file5StandardIdByMd5);
    const fileByMd5 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file5StandardIdByMd5 },
    });
    expect(fileByMd5?.data?.stixCyberObservable.standard_id).toEqual(file5StandardIdByMd5);
  });

  it('should clean standard from x_opencti_stix_ids if correlated data is removed', async () => {
    // Scenario 1 (no change of standard_id)
    // -------------------------------------
    // UPDATE StixFile1 to remove sha256 (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file1RemoveSha256Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-256',
      value: [null],
    }];
    const file1RemoveSha256Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file1Id,
        input: file1RemoveSha256Input,
      },
    });
    const file1RemoveSha256 = file1RemoveSha256Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file1RemoveSha256?.standard_id).toEqual(file1StandardIdByMd5);
    expect(file1RemoveSha256?.x_opencti_stix_ids).toEqual([file1StandardIdBySha1]);
    // UPDATE StixFile1 to remove SHA1 (standard_id based on MD5) (x_opencti_stix_ids empty).
    const file1RemoveSha1Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-1',
      value: [null],
    }];
    const file1RemoveSha1Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file1Id,
        input: file1RemoveSha1Input,
      },
    });
    const file1RemoveSha1 = file1RemoveSha1Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file1RemoveSha1?.standard_id).toEqual(file1StandardIdByMd5);
    expect(file1RemoveSha1?.x_opencti_stix_ids).toEqual([]);
    // Verify there is only one file in elastic
    const file1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file1StandardIdByMd5 },
    });
    expect(file1?.data?.stixCyberObservable.standard_id).toEqual(file1StandardIdByMd5);

    // Scenario 2 (standard_id changes)
    // --------------------------------
    // UPDATE StixFile3 to remove sha256 (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file3RemoveSha256Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-256',
      value: [null],
    }];
    const file3RemoveSha256Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file3Id,
        input: file3RemoveSha256Input,
      },
    });
    const file3RemoveSha256 = file3RemoveSha256Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file3RemoveSha256?.standard_id).toEqual(file3StandardIdByMd5);
    expect(file3RemoveSha256?.x_opencti_stix_ids).toEqual([file3StandardIdBySha1]);
    // UPDATE StixFile3 to remove MD5 (standard_id based on SHA1) (x_opencti_stix_ids empty).
    const file3RemoveMd5Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/MD5',
      value: [null],
    }];
    const file3RemoveMd5Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file3Id,
        input: file3RemoveMd5Input,
      },
    });
    const file3RemoveMd5 = file3RemoveMd5Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file3RemoveMd5?.standard_id).toEqual(file3StandardIdBySha1);
    expect(file3RemoveMd5?.x_opencti_stix_ids).toEqual([]);
    // UPDATE StixFile2 to remove MD5 (standard_id based on SHA1) (x_opencti_stix_ids has standard_SHA256).
    const file2RemoveMd5Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/MD5',
      value: [null],
    }];
    const file2RemoveMd5Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2Id,
        input: file2RemoveMd5Input,
      },
    });
    const file2RemoveMd5 = file2RemoveMd5Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file2RemoveMd5?.standard_id).toEqual(file2StandardIdBySha1);
    expect(file2RemoveMd5?.x_opencti_stix_ids).toEqual([file2StandardIdBySha256]);
    // UPDATE StixFile2 to remove SHA1 (standard_id based on SHA256) (x_opencti_stix_ids empty).
    const file2RemoveSha1Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-1',
      value: [null],
    }];
    const file2RemoveSha1Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2Id,
        input: file2RemoveSha1Input,
      },
    });
    const file2RemoveSha1 = file2RemoveSha1Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file2RemoveSha1?.standard_id).toEqual(file2StandardIdBySha256);
    expect(file2RemoveSha1?.x_opencti_stix_ids).toEqual([]);
    // Verify there is only one file in elastic
    const file2 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file2StandardIdBySha256 },
    });
    expect(file2?.data?.stixCyberObservable.standard_id).toEqual(file2StandardIdBySha256);
  });

  it('should update correctly with ADD operation (with hashes changes)', async () => {
    const input: EditInput[] = [
      {
        key: 'hashes',
        object_path: '/hashes/MD5',
        value: ['4fd8ed3f6d0d460e38fde11a12f45240']
      },
      {
        key: IDS_STIX,
        operation: EditOperation.Add,
        value: [
          'test--f7484d13-b10c-4ea3-a9a9-6c0f20076157',
          'test--3013fc4a-edfd-455b-92e6-aa359e633e48',
        ]
      }
    ];
    const result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: { id: file4Id, input }
    });
    const data = result.data?.stixCyberObservableEdit?.fieldPatch;
    expect(data.x_opencti_stix_ids).toEqual([
      'test--f7484d13-b10c-4ea3-a9a9-6c0f20076157',
      'test--3013fc4a-edfd-455b-92e6-aa359e633e48',
      ...file4StixIds
    ]);
  });

  it('should update correctly with REPLACE operation (with hashes changes)', async () => {
    const input: EditInput[] = [
      {
        key: 'hashes',
        object_path: '/hashes/MD5',
        value: ['9d03f4c2dae07ef9153d4b31328c110d']
      },
      {
        key: IDS_STIX,
        operation: EditOperation.Replace,
        value: ['test--3343c3cb-9102-4ff9-a391-881b0297a58d']
      }
    ];
    const result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: { id: file4Id, input }
    });
    const data = result.data?.stixCyberObservableEdit?.fieldPatch;
    expect(data.x_opencti_stix_ids).toEqual(['test--3343c3cb-9102-4ff9-a391-881b0297a58d', ...file4StixIds]);
  });

  it('should update correctly with REMOVE operation (with hashes changes)', async () => {
    const input: EditInput[] = [
      {
        key: 'hashes',
        object_path: '/hashes/MD5',
        value: ['7736ca3dc45dfb553f655bd36bab1773']
      },
      {
        key: IDS_STIX,
        operation: EditOperation.Remove,
        value: ['test--3343c3cb-9102-4ff9-a391-881b0297a58d']
      }
    ];
    const result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: { id: file4Id, input }
    });
    const data = result.data?.stixCyberObservableEdit?.fieldPatch;
    expect(data.x_opencti_stix_ids).toEqual(file4StixIds);
  });
});
