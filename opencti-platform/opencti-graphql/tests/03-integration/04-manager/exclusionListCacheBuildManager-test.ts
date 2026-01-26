import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import Upload from 'graphql-upload/Upload.mjs';
import { testContext } from '../../utils/testQuery';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR } from '../../../src/schema/stixCyberObservable';
import { buildCacheFromAllExclusionLists } from '../../../src/database/exclusionListCache';
import { checkExclusionLists } from '../../../src/utils/exclusionLists';
import { fileToReadStream } from '../../../src/database/file-storage';

describe('Exclusion list cache build manager tests ', () => {
  const context = testContext;
  let exclusionListIPId = '';
  let exclusionListDomainId = '';
  const exclusionListIpValuesFile = 'exclusionListIPValues.txt';
  const exclusionListDomainValuesFIle = 'exclusionListDomainValues.txt';

  const CREATE_FILE_MUTATION = gql`
    mutation exclusionListFileAdd($input: ExclusionListFileAddInput!) {
      exclusionListFileAdd(input: $input) {
        id
      }
    }
  `;

  const DELETE_MUTATION = gql`
        mutation exclusionListDelete($id: ID!) {
            exclusionListDelete(id: $id)
        }
    `;

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
  beforeAll(async () => {
    const ipValuesUpload = createUploadFile('./tests/data/exclusionLists/', exclusionListIpValuesFile);
    const exclusionListIP = await queryAsAdminWithSuccess({
      query: CREATE_FILE_MUTATION,
      variables: {
        input: {
          name: 'test_ip_list',
          description: 'test_description',
          exclusion_list_entity_types: [ENTITY_IPV4_ADDR],
          file: ipValuesUpload
        }
      }
    });
    exclusionListIPId = exclusionListIP.data?.exclusionListFileAdd.id;
    const domainValuesUpload = createUploadFile('./tests/data/exclusionLists/', exclusionListDomainValuesFIle);
    const exclusionListDomain = await queryAsAdminWithSuccess({
      query: CREATE_FILE_MUTATION,
      variables: {
        input: {
          name: 'test_domain_list',
          description: 'test_description',
          exclusion_list_entity_types: [ENTITY_DOMAIN_NAME],
          file: domainValuesUpload
        }
      }
    });
    exclusionListDomainId = exclusionListDomain.data?.exclusionListFileAdd.id;
  });
  afterAll(async () => {
    await queryAsAdminWithSuccess({
      query: DELETE_MUTATION,
      variables: {
        id: exclusionListIPId
      }
    });
    await queryAsAdminWithSuccess({
      query: DELETE_MUTATION,
      variables: {
        id: exclusionListDomainId
      }
    });
  });
  it('should build cache from current exclusion lists', async () => {
    const builtCache = await buildCacheFromAllExclusionLists(context);
    expect(builtCache).toBeDefined();
    expect(builtCache.length).toEqual(2);
    const ipCache = builtCache.filter((c) => c.id === exclusionListIPId);
    expect(ipCache.length).toEqual(1);
    expect(ipCache[0].types).toEqual([ENTITY_IPV4_ADDR]);
    expect(ipCache[0].values.length).toEqual(3);
    expect(checkExclusionLists('127.0.0.1', ENTITY_IPV4_ADDR, ipCache)).toBeTruthy();
    expect(checkExclusionLists('10.10.0.10', ENTITY_IPV4_ADDR, ipCache)).toBeTruthy();
    expect(checkExclusionLists('2.2.2.2', ENTITY_IPV4_ADDR, ipCache)).toBeTruthy();
    const domainCache = builtCache.filter((c) => c.id === exclusionListDomainId);
    expect(domainCache.length).toEqual(1);
    expect(domainCache[0].types).toEqual([ENTITY_DOMAIN_NAME]);
    expect(domainCache[0].values.length).toEqual(3);
    expect(checkExclusionLists('google.com', ENTITY_DOMAIN_NAME, domainCache)).toBeTruthy();
    expect(checkExclusionLists('filigran.io', ENTITY_DOMAIN_NAME, domainCache)).toBeTruthy();
    expect(checkExclusionLists('www.test.net', ENTITY_DOMAIN_NAME, domainCache)).toBeTruthy();
  });
});
