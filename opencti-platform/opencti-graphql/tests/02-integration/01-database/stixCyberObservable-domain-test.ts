import { describe, it, expect } from 'vitest';
import { Readable } from 'stream';
import { addStixCyberObservable, stixCyberObservableDelete } from '../../../src/domain/stixCyberObservable';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { AuthContext } from '../../../src/types/user';
import { mergeEntities, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import type { BasicStoreCommon } from '../../../src/types/store';
import { requestFileFromStorageAsAdmin } from '../../utils/testQueryHelper';
import { paginatedForPathWithEnrichment } from '../../../src/modules/internal/document/document-domain';
import { logApp } from '../../../src/config/conf';

describe('Testing Artifact merge with files on S3', () => {
  const adminContext: AuthContext = { user: ADMIN_USER, tracing: undefined, source: 'stixCyberObservableDomain-test', otp_mandatory: false };
  let artifact1Id = '';
  let artifact1: any;
  let artifact2: any;

  it('should create artifacts for test purpose', async () => {
    // GIVEN a first Artifact with one file
    const inputArtifact1 = {
      type: 'Artifact',
      Artifact: {
        payload_bin: '',
        file: {
          createReadStream: () => Readable.from('This is a file content for the first Artifact.'),
          filename: 'testing merge artifact with spaces 1.txt',
          mimetype: 'plain/text'
        },
        x_opencti_description: 'This is the first Artifact.',
        hashes: [],
      }
    };
    artifact1 = await addStixCyberObservable(adminContext, ADMIN_USER, inputArtifact1);
    artifact1Id = artifact1.id;

    // AND a second Artifact with one another file
    const inputArtifact2 = {
      type: 'Artifact',
      Artifact: {
        payload_bin: '',
        file: {
          createReadStream: () => Readable.from('This is a file content for the second Artifact.'),
          filename: 'testing merge artifact 2.json',
          mimetype: 'application/json'
        },
        x_opencti_description: '{ \'key\':\'value for artifact 2\'} }',
        hashes: [],
      }
    };
    artifact2 = await addStixCyberObservable(adminContext, ADMIN_USER, inputArtifact2);
  });

  it('should merge and files from both artifact be on the final merged artifact', async () => {
    // WHEN merge of 2 into 1 is called (via taskManager executeMerge)
    logApp.info(`Merging ${artifact2.internal_id} into ${artifact1.internal_id}`);
    await mergeEntities(testContext, ADMIN_USER, artifact1.internal_id, [
      artifact2.internal_id,
    ]);

    // THEN all file can be found on Artifact merged
    const mergedArtifact = await storeLoadByIdWithRefs(testContext, ADMIN_USER, artifact1.id) as BasicStoreCommon;

    // All files should be listed in x_opencti_files
    expect(mergedArtifact.x_opencti_files?.length).toBe(2);
    if (mergedArtifact.x_opencti_files) {
      for (let i = 0; i < mergedArtifact.x_opencti_files?.length; i += 1) {
        const file = mergedArtifact.x_opencti_files[i];
        expect(file.name).oneOf(['testing merge artifact 2.json', 'testing merge artifact with spaces 1.txt']);
        // All files should be downloadable from S3
        await requestFileFromStorageAsAdmin(file.id); // expect no exception throw
      }
    }

    // The query that is used on frontend should give the right files too
    const fileListForUI = await paginatedForPathWithEnrichment(testContext, ADMIN_USER, `import/${mergedArtifact.entity_type}/${mergedArtifact.id}`, mergedArtifact.id, {});

    const listOfFiles = fileListForUI.edges;
    expect(listOfFiles.length).toBe(2);

    for (let i = 0; i < listOfFiles.length; i += 1) {
      const file = listOfFiles[i].node;
      expect(file.name).oneOf(['testing merge artifact 2.json', 'testing merge artifact with spaces 1.txt']);

      // All files should be downloadable from S3
      await requestFileFromStorageAsAdmin(file.id); // expect no exception throw
    }
  });

  it('should delete created artifact', async () => {
    await stixCyberObservableDelete(adminContext, ADMIN_USER, artifact1Id);
  });
});
