import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { type EditInput, type StixFileAddInput } from '../../../src/generated/graphql';
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
};

const FILE2 = {
  name: 'file2',
  md5: '1c1c96fd2cf8330db0bfa936ce82f3b9',
  sha1: 'cb99b709a1978bd205ab9dfd4c5aaa1fc91c7523',
};

const FILE3 = {
  name: 'file3',
  md5: '2548729e9c3c60cc3789dfb2408e475d',
  sha1: 'd5b0a58bc47161b1b8a831084b366f757c4f0b11',
};

const FILE4 = {
  name: 'file4',
  md5: '33e28153f08dcd28a4c4292ad4c866af',
  sha1: '1b641bf4f6b84efcd42920ff1a88ff2f97fb9d08',
};

const FILE5 = {
  name: 'file5',
  md5: '025ad219ece1125a8f5a0e74e32676cb',
  sha1: 'c1750bee9c1f7b5dd6f025b645ab6eba5df94175',
};

describe('Observables with hashes: management of other stix ids', () => {
  let file1Id: string;
  const file1StandardIdByName = generateStandardId('StixFile', { name: FILE1.name, });
  const file1StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE1.sha1 } });
  const file1StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE1.md5 } });

  let file2Id: string;
  const file2StandardIdByName = generateStandardId('StixFile', { name: FILE2.name, });
  const file2StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE2.sha1 } });
  const file2StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE2.md5 } });

  let file3Id: string;
  const file3StandardIdByName = generateStandardId('StixFile', { name: FILE3.name, });
  const file3StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE3.sha1 } });
  const file3StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE3.md5 } });

  let file4Id: string;
  const file4StandardIdByName = generateStandardId('StixFile', { name: FILE4.name, });
  const file4StandardIdBySha1 = generateStandardId('StixFile', { hashes: { 'SHA-1': FILE4.sha1 } });
  const file4StandardIdByMd5 = generateStandardId('StixFile', { hashes: { MD5: FILE4.md5 } });

  let file5Id: string;
  const file5StandardIdByName = generateStandardId('StixFile', { name: FILE5.name, });
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
    const file1WithNameInput: StixFileAddInput = {
      name: FILE1.name,
    };
    const file1WithNameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file1WithNameInput },
    });
    const file1WithName = file1WithNameResult?.data?.stixCyberObservableAdd;
    file1Id = file1WithName?.id;
    expect(file1WithName?.standard_id).toEqual(file1StandardIdByName);
    expect(file1WithName?.x_opencti_stix_ids).toEqual([]);
    // UPSERT StixFile1 with name and SHA1 (standard_id based on SHA1) (x_opencti_stix_ids has standard_name).
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
    expect(file1WithNameSha1?.id).toEqual(file1Id);
    expect(file1WithNameSha1?.standard_id).toEqual(file1StandardIdBySha1);
    expect(file1WithNameSha1?.x_opencti_stix_ids).toEqual([file1StandardIdByName]);
    // UPSERT StixFile1 with name, SHA1 and MD5 (standard_id based on MD5) (x_opencti_stix_ids has standard_name, standard_SHA1).
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
    expect(file1WithNameSha1Md5?.id).toEqual(file1Id);
    expect(file1WithNameSha1Md5?.standard_id).toEqual(file1StandardIdByMd5);
    expect(file1WithNameSha1Md5?.x_opencti_stix_ids).toEqual([file1StandardIdBySha1, file1StandardIdByName]);
    // Verify there is only one file in elastic
    const file1 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file1StandardIdBySha1 },
    });
    expect(file1?.data?.stixCyberObservable.standard_id).toEqual(file1StandardIdByMd5);
  });

  it('should replace standard_id and add old one in x_opencti_stix_ids if prior data arrives by Update', async () => {
    // Create StixFile2 with only name (standard_id based on name) (x_opencti_stix_ids empty).
    const file2WithNameInput: StixFileAddInput = {
      name: FILE2.name,
    };
    const file2WithNameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file2WithNameInput },
    });
    const file2WithName = file2WithNameResult?.data?.stixCyberObservableAdd;
    file2Id = file2WithName?.id;
    expect(file2WithName?.standard_id).toEqual(file2StandardIdByName);
    expect(file2WithName?.x_opencti_stix_ids).toEqual([]);
    // UPDATE StixFile2 with SHA1 (standard_id based on SHA1) (x_opencti_stix_ids has standard_name).
    const file2WithNameSha1Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/SHA-1',
      value: [FILE2.sha1]
    }];
    const file2WithNameSha1Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2Id,
        input: file2WithNameSha1Input,
      },
    });
    const file2WithNameSha1 = file2WithNameSha1Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file2WithNameSha1?.standard_id).toEqual(file2StandardIdBySha1);
    expect(file2WithNameSha1?.x_opencti_stix_ids).toEqual([file2StandardIdByName]);
    // UPDATE StixFile2 with name, SHA1 and MD5 (standard_id based on MD5) (x_opencti_stix_ids has standard_name, standard_SHA1).
    const file2WithNameSha1Md5Input: EditInput[] = [{
      key: 'hashes',
      object_path: '/hashes/MD5',
      value: [FILE2.md5]
    }];
    const file2WithNameSha1Md5Result = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file2Id,
        input: file2WithNameSha1Md5Input,
      },
    });
    const file2WithNameSha1Md5 = file2WithNameSha1Md5Result?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file2WithNameSha1Md5?.standard_id).toEqual(file2StandardIdByMd5);
    expect(file2WithNameSha1Md5?.x_opencti_stix_ids).toEqual([file2StandardIdBySha1, file2StandardIdByName]);
    // Verify there is only one file in elastic
    const file2 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file2StandardIdBySha1 },
    });
    expect(file2?.data?.stixCyberObservable.standard_id).toEqual(file2StandardIdByMd5);
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
    // UPSERT StixFile3 with MD5, SHA1 and name (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1, standard_name).
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
    expect(file3WithMd5Sha1Name?.x_opencti_stix_ids).toEqual([file3StandardIdBySha1, file3StandardIdByName]);
    // Verify there is only one file in elastic
    const file3 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file3StandardIdBySha1 },
    });
    expect(file3?.data?.stixCyberObservable.standard_id).toEqual(file3StandardIdByMd5);
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
    // UPDATE StixFile4 with MD5, SHA1 and name (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1, standard_name).
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
    expect(file4WithMd5Sha1Name?.x_opencti_stix_ids).toEqual([file4StandardIdBySha1, file4StandardIdByName]);
    // Verify there is only one file in elastic
    const file4 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file4StandardIdBySha1 },
    });
    expect(file4?.data?.stixCyberObservable.standard_id).toEqual(file4StandardIdByMd5);
  });

  it.skip('should merge observables and x_opencti_stix_ids', async () => {
    // Create StixFile5 with name (standard_id based on name) (x_opencti_stix_ids empty).
    const file5WithNameInput: StixFileAddInput = {
      name: FILE5.name,
    };
    const file5WithNameResult = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file5WithNameInput },
    });
    const file5WithName = file5WithNameResult?.data?.stixCyberObservableAdd;
    expect(file5WithName?.standard_id).toEqual(file5StandardIdByName);
    expect(file5WithName?.x_opencti_stix_ids).toEqual([]);
    // Create StixFile6 with MD5 (standard_id based on MD5) (x_opencti_stix_ids empty).
    const file5WithMd5Input: StixFileAddInput = {
      hashes: [
        { algorithm: 'MD5', hash: FILE5.md5 }
      ]
    };
    const file5WithMd5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file5WithMd5Input },
    });
    const file5WithMd5 = file5WithMd5Result?.data?.stixCyberObservableAdd;
    file5Id = file5WithMd5?.id;
    expect(file5WithMd5?.id).not.toEqual(file5WithName?.id);
    expect(file5WithMd5?.standard_id).toEqual(file5StandardIdByMd5);
    expect(file5WithMd5?.x_opencti_stix_ids).toEqual([]);
    // Create StixFile7 with MD5 and name => Merge (standard_id based on MD5) (x_opencti_stix_ids has standard_name).
    const file5WithNameMd5Input: StixFileAddInput = {
      name: FILE5.name,
      hashes: [
        { algorithm: 'MD5', hash: FILE5.md5 }
      ]
    };
    const file5WithNameMd5Result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: file5WithNameMd5Input },
    });
    const file5WithNameMd5 = file5WithNameMd5Result?.data?.stixCyberObservableAdd;
    expect(file5WithNameMd5?.id).toEqual(file5Id);
    expect(file5WithNameMd5?.standard_id).toEqual(file5StandardIdByMd5);
    expect(file5WithNameMd5?.x_opencti_stix_ids).toEqual([file5StandardIdByName]);
    // Verify there is only one file in elastic
    const file5 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file5StandardIdByMd5 },
    });
    expect(file5?.data?.stixCyberObservable.standard_id).toEqual(file5StandardIdByMd5);
  });

  it('should clean standard from x_opencti_stix_ids if correlated data is removed', async () => {
    // Scenario 1 (no change of standard_id)
    // -------------------------------------
    // UPDATE StixFile1 to remove name (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file1RemoveNameInput: EditInput[] = [{
      key: 'name',
      value: [null],
    }];
    const file1RemoveNameResult = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file1Id,
        input: file1RemoveNameInput,
      },
    });
    const file1RemoveName = file1RemoveNameResult?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file1RemoveName?.standard_id).toEqual(file1StandardIdByMd5);
    expect(file1RemoveName?.x_opencti_stix_ids).toEqual([file1StandardIdBySha1]);
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
    // UPDATE StixFile3 to remove name (standard_id based on MD5) (x_opencti_stix_ids has standard_SHA1).
    const file3RemoveNameInput: EditInput[] = [{
      key: 'name',
      value: [null],
    }];
    const file3RemoveNameResult = await queryAsAdmin({
      query: EDIT_STIX_FILE_QUERY,
      variables: {
        id: file3Id,
        input: file3RemoveNameInput,
      },
    });
    const file3RemoveName = file3RemoveNameResult?.data?.stixCyberObservableEdit?.fieldPatch;
    expect(file3RemoveName?.standard_id).toEqual(file3StandardIdByMd5);
    expect(file3RemoveName?.x_opencti_stix_ids).toEqual([file3StandardIdBySha1]);
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
    // UPDATE StixFile2 to remove MD5 (standard_id based on SHA1) (x_opencti_stix_ids has standard_name).
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
    expect(file2RemoveMd5?.x_opencti_stix_ids).toEqual([file2StandardIdByName]);
    // UPDATE StixFile2 to remove SHA1 (standard_id based on name) (x_opencti_stix_ids empty).
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
    expect(file2RemoveSha1?.standard_id).toEqual(file2StandardIdByName);
    expect(file2RemoveSha1?.x_opencti_stix_ids).toEqual([]);
    // Verify there is only one file in elastic
    const file2 = await queryAsAdmin({
      query: FIND_BY_ID_QUERY,
      variables: { id: file2StandardIdByName },
    });
    expect(file2?.data?.stixCyberObservable.standard_id).toEqual(file2StandardIdByName);
  });
});
