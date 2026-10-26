import { logApp, NODE_INSTANCE_ID } from '../config/conf';
import { lockResources } from '../lock/master-lock';
import { backfillIdentities } from '../database/lockfree/backfill';
import { isIdentityBackfillDone, LOCKFREE_INGESTION_ENABLED, markIdentityBackfillDone } from '../database/lockfree/ingestion';
import { Settler } from '../database/lockfree/settler';
import { type ManagerDefinition, registerManager } from './managerModule';

// Settler of the lock-free write path (app:lockfree_ingestion:enabled): applies the work the writes leave behind
// (lists of relationships on shared entities, duplicates found after both were created), from the durable queue.
// Every platform node runs one (the lock is per node): they share the queue through its consumer group. Before
// the first worker import goes lock-free, one node registers the existing data in the identity index.
const SETTLE_EVERY_MS = 250;
const settler = new Settler({ consumer: `settler-${NODE_INSTANCE_ID}` });

// The backfill lock, or nothing when another node holds it (it is running the backfill)
const tryLockBackfill = async () => {
  try {
    return await lockResources(['lockfree_identity_backfill'], { retryCount: 0 });
  } catch {
    return undefined;
  }
};

const ensureIdentityBackfill = async () => {
  if (await isIdentityBackfillDone()) return;
  const lock = await tryLockBackfill();
  if (!lock) return;
  try {
    if (await isIdentityBackfillDone()) return;
    logApp.info('[OPENCTI-MODULE] Lock-free ingestion: identity backfill started');
    const outcome = await backfillIdentities();
    await markIdentityBackfillDone();
    logApp.info('[OPENCTI-MODULE] Lock-free ingestion: identity backfill done, worker imports now lock-free', outcome);
  } finally {
    await lock.unlock();
  }
};

const lockfreeSettlerHandler = async () => {
  await ensureIdentityBackfill();
  await settler.flush();
};

const LOCKFREE_SETTLER_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'LOCKFREE_SETTLER_MANAGER',
  label: 'Lock-free ingestion settler',
  executionContext: 'lockfree_settler_manager',
  cronSchedulerHandler: {
    handler: lockfreeSettlerHandler,
    interval: 10000,
    runOnStart: true,
    infiniteInterval: SETTLE_EVERY_MS,
    lockKey: `lockfree_settler_manager_lock_${NODE_INSTANCE_ID}`,
  },
  enabledByConfig: LOCKFREE_INGESTION_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(LOCKFREE_SETTLER_MANAGER_DEFINITION);
