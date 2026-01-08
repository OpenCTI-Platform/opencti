import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import { createReadStream } from 'node:fs';
import {
  ADMIN_API_TOKEN,
  ADMIN_USER,
  createHttpClient,
  DATA_FILE_TEST,
  executeExternalQuery,
  FIFTEEN_MINUTES,
  SYNC_DIRECT_START_REMOTE_URI,
  SYNC_TEST_REMOTE_URI,
  testContext,
} from '../../utils/testQuery';
import { findById as findUserById } from '../../../src/domain/user';
import { checkPostSyncContent, checkPreSyncContent, REPORT_QUERY, SYNC_CREATION_QUERY, SYNC_START_QUERY, UPLOADED_FILE_SIZE } from '../sync-utils';
import { SYSTEM_USER } from '../../../src/utils/access';
import { wait } from '../../../src/database/utils';
import { stixCoreObjectImportPush } from '../../../src/domain/stixCoreObject';
import gql from 'graphql-tag';

const DELETE_USER_QUERY = gql`
    mutation userDelete($id: ID!) {
        userEdit(id: $id) {
            delete
        }
    }
`;

const READ_USER_QUERY = gql`
    query user($id: String!) {
        user(id: $id) {
            id
            name
            description
            user_confidence_level {
                max_confidence
            }
        }
    }
`;

describe('Database sync direct', () => {
  it(
    'Should direct sync succeed and add auto_user',
    async () => {
      const client = createHttpClient();
      // Pre check
      const { objectMap, relMap, initStixReport } = await checkPreSyncContent();
      // Upload a file
      const file = {
        createReadStream: () => createReadStream('./tests/data/DATA-TEST-STIX2_v2.json'),
        filename: DATA_FILE_TEST,
        mimetype: 'application/json',
      };
      await stixCoreObjectImportPush(testContext, SYSTEM_USER, 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7', file);
      // Need to create the synchronizer on the remote host
      const SYNC_CREATE = {
        input: {
          name: 'SYNC',
          uri: SYNC_TEST_REMOTE_URI,
          listen_deletion: true,
          no_dependencies: false,
          stream_id: 'live',
          token: ADMIN_API_TOKEN,
          user_id: ADMIN_USER.id,
          automatic_user: false,
        },
      };
      const synchronizer = await executeExternalQuery(client, SYNC_DIRECT_START_REMOTE_URI, SYNC_CREATION_QUERY, SYNC_CREATE);
      console.log('synchronizer', synchronizer);
      // Start the sync
      const syncId = synchronizer.synchronizerAdd.id;
      await executeExternalQuery(client, SYNC_DIRECT_START_REMOTE_URI, SYNC_START_QUERY, { id: syncId });
      // Wait 2 min sync to consume all the stream
      await wait(120000);
      // Post check
      await checkPostSyncContent(SYNC_DIRECT_START_REMOTE_URI, objectMap, relMap, initStixReport);
      // Check file availability
      const reportData = await executeExternalQuery(client, SYNC_DIRECT_START_REMOTE_URI, REPORT_QUERY, {
        id: 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7',
      });
      const files = reportData.report.importFiles.edges;
      expect(files.length).toEqual(1);
      const uploadedFile = R.head(files).node;
      expect(uploadedFile.name).toEqual(DATA_FILE_TEST);
      expect(uploadedFile.size).toEqual(UPLOADED_FILE_SIZE);
      const userIdCreated = synchronizer.synchronizerAdd.user_id;
      const createdUser = await findUserById(testContext, ADMIN_USER, userIdCreated);
      expect(createdUser.name).toBe('[F] Taxii ingester for integration test');
      // Delete just created user
      await adminQuery({
        query: DELETE_USER_QUERY,
        variables: { id: createdUser.id },
      });
      // Verify no longer found
      const queryResult = await adminQuery({ query: READ_USER_QUERY, variables: { id: createdUser.id } });
      expect(queryResult).not.toBeNull();
      expect(queryResult.data.user).toBeNull();
    },
    FIFTEEN_MINUTES,
  );
});
