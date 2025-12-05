import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { stixLoadByIds } from '../../../src/database/middleware';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const CREATE_STIX_FILE_QUERY = gql`
  mutation CreateStixFile($input: StixFileAddInput) {
    stixCyberObservableAdd(type: "StixFile", StixFile: $input) {
      id
      standard_id
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

const DELETE_STIX_FILE_QUERY = gql`
  mutation DeleteStixFile($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
    }
  }
`;

describe('Hash enrichment', () => {
  let fileWithMultipleHashesId: string;
  let fileWithMultipleHashesStandardId: string;

  const FILE_HASHES = {
    MD5: '5d41402abc4b2a76b9719d911017c592',
    'SHA-256': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
  };

  beforeAll(async () => {
    const fileWithMultipleHashesInput = {
      name: 'test-file-for-enrichment.exe',
      hashes: [
        { algorithm: 'MD5', hash: FILE_HASHES.MD5 },
        { algorithm: 'SHA-256', hash: FILE_HASHES['SHA-256'] }
      ]
    };
    
    const result = await queryAsAdmin({
      query: CREATE_STIX_FILE_QUERY,
      variables: { input: fileWithMultipleHashesInput }
    });
    
    const file = result.data?.stixCyberObservableAdd;
    fileWithMultipleHashesId = file.id;
    fileWithMultipleHashesStandardId = file.standard_id;
  });

  afterAll(async () => {
    if (fileWithMultipleHashesId) {
      await queryAsAdmin({
        query: DELETE_STIX_FILE_QUERY,
        variables: { id: fileWithMultipleHashesId }
      });
    }
  });

  it('should enrich StixFile loaded with only SHA-256 with MD5 from existing object', async () => {
    const stixObjects = await stixLoadByIds(
      testContext,
      ADMIN_USER,
      [fileWithMultipleHashesStandardId],
      { resolveStixFiles: true }
    );
    
    expect(stixObjects).toBeDefined();
    expect(stixObjects.length).toBe(1);
    
    const stixFile = stixObjects[0];
    
    expect(stixFile.hashes).toBeDefined();
    expect(stixFile.hashes.MD5).toBe(FILE_HASHES.MD5);
    expect(stixFile.hashes['SHA-256']).toBe(FILE_HASHES['SHA-256']);
    
    expect(stixFile.id).toBe(fileWithMultipleHashesStandardId);
  });

  it('should work with Artifact objects as well', async () => {
    const CREATE_ARTIFACT_QUERY = gql`
      mutation CreateArtifact($input: ArtifactAddInput) {
        stixCyberObservableAdd(type: "Artifact", Artifact: $input) {
          id
          standard_id
          ... on Artifact {
            hashes {
              algorithm
              hash
            }
          }
        }
      }
    `;
    
    const artifactInput = {
      hashes: [
        { algorithm: 'MD5', hash: 'aabbccdd11223344556677889900aabb' },
        { algorithm: 'SHA-256', hash: 'ccdd11223344556677889900aabbccdd11223344556677889900aabbccdd1122' }
      ]
    };
    
    const createResult = await queryAsAdmin({
      query: CREATE_ARTIFACT_QUERY,
      variables: { input: artifactInput }
    });
    
    const artifact = createResult.data?.stixCyberObservableAdd;
    const artifactId = artifact.id;
    const artifactStandardId = artifact.standard_id;
    
    try {
      const stixObjects = await stixLoadByIds(
        testContext,
        ADMIN_USER,
        [artifactStandardId],
        { resolveStixFiles: true }
      );
      
      expect(stixObjects.length).toBe(1);
      const stixArtifact = stixObjects[0];
      
      expect(stixArtifact.hashes).toBeDefined();
      expect(stixArtifact.hashes.MD5).toBe('aabbccdd11223344556677889900aabb');
      expect(stixArtifact.hashes['SHA-256']).toBe('ccdd11223344556677889900aabbccdd11223344556677889900aabbccdd1122');
      
    } finally {
      const DELETE_ARTIFACT_QUERY = gql`
        mutation DeleteArtifact($id: ID!) {
          stixCyberObservableEdit(id: $id) {
            delete
          }
        }
      `;
      await queryAsAdmin({
        query: DELETE_ARTIFACT_QUERY,
        variables: { id: artifactId }
      });
    }
  });
});