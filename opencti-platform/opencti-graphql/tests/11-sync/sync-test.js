import { beforeAll, describe, it } from 'vitest';
import {
  FIFTEEN_MINUTES,
  FIVE_MINUTES,
  ONE_MINUTE,
  SYNC_DIRECT_START_REMOTE_URI,
  SYNC_LIVE_START_REMOTE_URI,
  SYNC_RAW_START_REMOTE_URI,
  SYNC_RESTORE_START_REMOTE_URI,
} from '../utils/testQuery';
import { uploadReportFile, waitForRemotePlatform } from './sync-utils';
import { syncRaw } from './00-Raw/sync-raw';
import { syncLive } from './01-Live/sync-live';
import { syncDirect } from './02-Direct/sync-direct';
import { syncRestore } from './03-Restore/sync-restore';

const REMOTE_URIS = [SYNC_RAW_START_REMOTE_URI, SYNC_LIVE_START_REMOTE_URI, SYNC_DIRECT_START_REMOTE_URI, SYNC_RESTORE_START_REMOTE_URI];
// The 4 syncs only read this platform, and in CI each one writes to its own remote platform
// (own index prefix, Redis namespace, bucket and queues, see scripts/ci/ci-sync.env), so they run at the same time.
// They stay sequential when they share a remote platform (config/test.json points them all to the same one).
const describeSync = new Set(REMOTE_URIS).size === REMOTE_URIS.length ? describe.concurrent : describe;
describeSync('Database sync', () => {
  beforeAll(async () => {
    await Promise.all([...new Set(REMOTE_URIS)].map((remoteUri) => waitForRemotePlatform(remoteUri)));
    // Before any sync starts, so that no sync reads the streams while they change.
    // The raw sync stops before this last event (RAW_EVENTS_SIZE), and the live stream keeps its size (SYNC_LIVE_EVENTS_SIZE).
    await uploadReportFile();
  }, FIVE_MINUTES + ONE_MINUTE);

  it('Should python raw sync succeed', syncRaw, FIFTEEN_MINUTES);
  it('Should python live sync succeed', syncLive, FIFTEEN_MINUTES);
  it('Should direct sync succeed', syncDirect, FIFTEEN_MINUTES);
  it('Should backup/restore sync succeed', syncRestore, FIFTEEN_MINUTES);
});
