import { logApp } from '../../../config/conf';
import { RABBIT_QUEUE_PREFIX } from '../../../database/utils';
import { getCachedRabbitmqMetrics } from '../../../database/rabbitmq';
import { getEntitiesListFromCache } from '../../../database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../../schema/internalObject';
import { getPlatformUsageMetrics, withTimeout } from '../../../telemetry/platformHealthMetrics';
import { isConnectorStopped, refreshConnectorsLiveness } from '../../connector/connector-domain';
import type { CachedConnector } from '../../connector/connector-types';
import type { IngestionHealthFields } from '../../ingestionHealth/ingestionHealth-types';
import type { AuthContext, AuthUser } from '../../../types/user';

// The format XTM One reads (XTM-One-Platform/xtm-one dev-docs/platform-health.md, section 5): every key is optional,
// and XTM One ignores a snapshot of another format or over 256 KB.
export const XTM_ONE_HEALTH_SCHEMA_VERSION = 1;
// XTM One keeps 500 connectors at most.
const MAX_CONNECTORS = 500;

export interface XtmOneHealthConnector {
  id: string;
  name: string;
  // Expected to report: not stopped and followed by the ingestion health manager, so a silent one is a stale one.
  active: boolean;
  updated_at?: string;
  queue_messages: number;
}

export interface XtmOneHealthSnapshot {
  schema_version: number;
  connectors?: XtmOneHealthConnector[];
  rabbitmq?: { queue_messages: number; consumers: number };
  search_engine?: { status?: string; disk_used_percent?: number };
}

interface RabbitmqQueue {
  name: string;
  messages?: number;
  consumers?: number;
}

const toCount = (value: unknown) => (typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0);

const collect = async <T>(part: string, read: () => Promise<T>): Promise<T | undefined> => {
  try {
    return await withTimeout(read(), `Timeout collecting ${part}`);
  } catch (error: any) {
    // A part that cannot be read in time is left out: the snapshot rides on the registration heartbeat and never delays it.
    logApp.debug('[XTM One] Health snapshot part not collected', { part, cause: error?.message });
    return undefined;
  }
};

export const buildRabbitmqHealth = (stats: { consumers?: number; queues?: RabbitmqQueue[] }) => {
  const pushQueues = (stats.queues ?? []).filter((queue) => (queue?.name ?? '').startsWith(`${RABBIT_QUEUE_PREFIX}push_`));
  return {
    queue_messages: pushQueues.reduce((total, queue) => total + toCount(queue.messages), 0),
    consumers: Math.max(toCount(stats.consumers), ...pushQueues.map((queue) => toCount(queue.consumers))),
  };
};

type SnapshotConnector = CachedConnector & IngestionHealthFields & { last_seen_at?: string | null };

export const buildConnectorsHealth = (registeredConnectors: SnapshotConnector[], queues: RabbitmqQueue[]): XtmOneHealthConnector[] => {
  const messagesByQueue = new Map(queues.map((queue) => [queue.name, toCount(queue.messages)]));
  return registeredConnectors
    .filter((connector) => connector && !connector.built_in && connector.id)
    .slice(0, MAX_CONNECTORS)
    .map((connector) => {
      const entry: XtmOneHealthConnector = {
        id: connector.id,
        name: connector.title || connector.name || connector.id,
        // The ingestion health manager clears the health of a stopped connector at its next run
        active: !isConnectorStopped(connector) && !!connector.ingestion_health,
        queue_messages: (messagesByQueue.get(`${RABBIT_QUEUE_PREFIX}push_${connector.id}`) ?? 0)
          + (messagesByQueue.get(`${RABBIT_QUEUE_PREFIX}listen_${connector.id}`) ?? 0),
      };
      if (connector.last_seen_at) {
        entry.updated_at = new Date(connector.last_seen_at).toISOString();
      }
      return entry;
    });
};

/**
 * The health snapshot sent with the XTM One registration: connectors, broker and search engine, each collected on
 * its own and left out when it cannot be read. XTM One turns it into the findings of its Platform Health page.
 */
export const buildXtmOneHealthSnapshot = async (context: AuthContext, user: AuthUser): Promise<XtmOneHealthSnapshot> => {
  const snapshot: XtmOneHealthSnapshot = { schema_version: XTM_ONE_HEALTH_SCHEMA_VERSION };
  const stats = await collect('rabbitmq', () => getCachedRabbitmqMetrics(context, user) as Promise<{ consumers?: number; queues?: RabbitmqQueue[] }>);
  if (stats) {
    snapshot.rabbitmq = buildRabbitmqHealth(stats);
  }
  const connectorsHealth = await collect('connectors', async () => {
    const cachedConnectors = await getEntitiesListFromCache<SnapshotConnector>(context, user, ENTITY_TYPE_CONNECTOR);
    return buildConnectorsHealth(await refreshConnectorsLiveness(cachedConnectors), stats?.queues ?? []);
  });
  if (connectorsHealth) {
    snapshot.connectors = connectorsHealth;
  }
  // The search engine health /health exposes, collected by the platform usage metrics manager
  const { es_status, es_disk_used_percent } = getPlatformUsageMetrics();
  if (es_status !== null || es_disk_used_percent !== null) {
    snapshot.search_engine = {
      ...(es_status !== null ? { status: es_status } : {}),
      ...(es_disk_used_percent !== null ? { disk_used_percent: es_disk_used_percent } : {}),
    };
  }
  return snapshot;
};
