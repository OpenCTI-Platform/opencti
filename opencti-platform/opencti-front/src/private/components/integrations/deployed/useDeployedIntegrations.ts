import { useMemo } from 'react';
import { v5 as uuidv5 } from 'uuid';
import { ConnectorsListQuery } from '@components/data/connectors/__generated__/ConnectorsListQuery.graphql';
import { ConnectorsStateQuery } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import { BUILT_IN_INTEGRATIONS, BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import { IngestionFeedsData, IngestionFeedsFormsData } from '@components/integrations/deployed/IngestionFeeds';
import { computeConnectorStatus } from '../../../../utils/Connector';

// Mirrors the backend: every built-in feed registers a technical queue
// connector whose id is derived from the ingestion id (uuid v5 in the OpenCTI
// namespace). Used to fold those connectors back into their feed entry.
const OPENCTI_NAMESPACE = 'b639ff3b-00eb-42ed-aa36-a8dd6f8fb4cf';
export const connectorIdFromIngestId = (id: string) => uuidv5(id, OPENCTI_NAMESPACE);

export type DeployedIntegrationStatus = 'active' | 'inactive' | 'processing';

export interface DeployedIntegrationItem {
  id: string;
  // 'connector' or the built-in feed kind
  kind: 'connector' | BuiltInIntegrationKind;
  // Facet/section identifier: connector_type for connectors, kind for feeds
  sectionKey: string;
  name: string;
  description?: string | null;
  logo?: string;
  status: DeployedIntegrationStatus;
  statusLabel: string;
  running?: boolean;
  messagesCount: number | null;
  lastRunDate: string | null;
  updatedAt: string | null;
  isManaged: boolean;
  uri?: string | null;
  userName?: string | null;
  detailUrl: string;
  searchText: string;
  // Raw merged connector record, needed by connector row actions
  connector?: ConnectorsListQuery['response']['connectors'][number] & Partial<ConnectorsStateQuery['response']['connectors'][number]>;
}

interface UseDeployedIntegrationsProps {
  connectorsListData?: ConnectorsListQuery['response'] | null;
  connectorsStateData?: ConnectorsStateQuery['response'] | null;
  feedsData?: IngestionFeedsData | null;
  formsData?: IngestionFeedsFormsData | null;
  logosBySlug: Map<string, string>;
}

const toSafeNumber = (value: unknown): number => {
  const nValue = Number(value);
  return Number.isFinite(nValue) ? nValue : 0;
};

const feedStatus = (running: boolean | null | undefined) => {
  return {
    status: (running ? 'active' : 'inactive') as DeployedIntegrationStatus,
    statusLabel: running ? 'active' : 'inactive',
  };
};

const buildSearchText = (parts: (string | null | undefined)[]): string => {
  return parts.filter((part) => !!part).join(' ').toLowerCase();
};

const builtInLabel = (kind: BuiltInIntegrationKind): string => {
  return BUILT_IN_INTEGRATIONS.find((definition) => definition.kind === kind)?.label ?? kind;
};

// Merges every deployed integration (registered connectors and built-in feed
// instances) into a single normalized list for the deployed marketplace view.
const useDeployedIntegrations = ({
  connectorsListData,
  connectorsStateData,
  feedsData,
  formsData,
  logosBySlug,
}: UseDeployedIntegrationsProps): DeployedIntegrationItem[] => {
  return useMemo(() => {
    const items: DeployedIntegrationItem[] = [];

    // Registered connectors, enriched with their live state and queue metrics.
    const queues = connectorsStateData?.rabbitMQMetrics?.queues ?? [];
    const queueMessagesByConnector = new Map<string, number>();
    for (const queue of queues) {
      if (!queue?.name) continue;
      const messages = toSafeNumber(queue.messages);
      let idx = queue.name.indexOf('push_');
      if (idx === -1) idx = queue.name.indexOf('listen_');
      if (idx === -1) continue;
      const connectorId = queue.name.substring(queue.name.indexOf('_', idx) + 1);
      if (!connectorId) continue;
      queueMessagesByConnector.set(connectorId, (queueMessagesByConnector.get(connectorId) ?? 0) + messages);
    }

    // Every built-in feed instance registers a technical queue connector: those
    // twins are folded into the feed entry (no duplicated card), and their
    // queue metrics are surfaced on the feed itself.
    const feedIds = [
      ...(feedsData?.ingestionRsss?.edges ?? []),
      ...(feedsData?.ingestionTaxiis?.edges ?? []),
      ...(feedsData?.ingestionTaxiiCollections?.edges ?? []),
      ...(feedsData?.ingestionCsvs?.edges ?? []),
      ...(feedsData?.ingestionJsons?.edges ?? []),
      ...(formsData?.forms?.edges ?? []),
    ].flatMap((edge) => (edge?.node ? [edge.node.id] : []));
    const feedTwinConnectorIds = new Set(feedIds.map((id) => connectorIdFromIngestId(id)));
    const feedQueueMessages = (feedId: string): number => {
      return queueMessagesByConnector.get(connectorIdFromIngestId(feedId)) ?? 0;
    };

    for (const connector of connectorsListData?.connectors ?? []) {
      if (connector.connector_type === 'internal') continue;
      if (feedTwinConnectorIds.has(connector.id)) continue;
      const state = connectorsStateData?.connectors?.find((s) => s.id === connector.id);
      const merged = { ...connector, ...state };
      const { status, label, processing } = computeConnectorStatus({
        manager_current_status: state?.manager_current_status,
        manager_requested_status: state?.manager_requested_status,
        active: state?.active,
      });
      let itemStatus: DeployedIntegrationStatus;
      if (processing) {
        itemStatus = 'processing';
      } else if (status === 'active') {
        itemStatus = 'active';
      } else {
        itemStatus = 'inactive';
      }
      const logoSlug = connector.manager_contract_excerpt?.slug;
      items.push({
        id: connector.id,
        kind: 'connector',
        sectionKey: connector.connector_type ?? 'UNKNOWN',
        name: connector.title ?? connector.name,
        description: connector.manager_contract_excerpt?.title,
        logo: logoSlug ? logosBySlug.get(logoSlug) : undefined,
        status: itemStatus,
        statusLabel: label,
        messagesCount: queueMessagesByConnector.get(connector.id) ?? 0,
        lastRunDate: null,
        updatedAt: connector.updated_at,
        isManaged: !!connector.is_managed,
        detailUrl: `/dashboard/integrations/connectors/${connector.id}`,
        searchText: buildSearchText([connector.title, connector.name, connector.connector_type]),
        connector: merged,
      });
    }

    // Built-in feed instances, one entry per deployed feed.
    for (const edge of feedsData?.synchronizers?.edges ?? []) {
      if (!edge?.node) continue;
      const node = edge.node;
      items.push({
        id: node.id,
        kind: 'sync',
        sectionKey: 'sync',
        name: node.name,
        description: node.uri,
        ...feedStatus(node.running),
        running: !!node.running,
        messagesCount: toSafeNumber(node.queue_messages),
        lastRunDate: (node.current_state_date as string | null) ?? null,
        updatedAt: null,
        isManaged: false,
        uri: node.uri,
        userName: node.user?.name,
        detailUrl: `/dashboard/integrations/feeds/sync/${node.id}`,
        searchText: buildSearchText([node.name, node.uri, builtInLabel('sync')]),
      });
    }

    const pushFeed = (
      kind: BuiltInIntegrationKind,
      node: {
        id: string;
        name: string;
        description?: string | null;
        uri?: string | null;
        ingestion_running?: boolean | null;
        last_execution_date?: string | null;
        updated_at?: string | null;
        user?: { readonly name: string } | null;
      },
    ) => {
      items.push({
        id: node.id,
        kind,
        sectionKey: kind,
        name: node.name,
        description: node.description,
        ...feedStatus(node.ingestion_running),
        running: !!node.ingestion_running,
        messagesCount: feedQueueMessages(node.id),
        lastRunDate: (node.last_execution_date as string | null) ?? null,
        updatedAt: (node.updated_at as string | null) ?? null,
        isManaged: false,
        uri: node.uri,
        userName: node.user?.name,
        detailUrl: `/dashboard/integrations/feeds/${kind}/${node.id}`,
        searchText: buildSearchText([node.name, node.description, node.uri, builtInLabel(kind)]),
      });
    };

    for (const edge of feedsData?.ingestionRsss?.edges ?? []) {
      if (edge?.node) pushFeed('rss', edge.node);
    }
    for (const edge of feedsData?.ingestionTaxiis?.edges ?? []) {
      if (edge?.node) pushFeed('taxii', edge.node);
    }
    for (const edge of feedsData?.ingestionTaxiiCollections?.edges ?? []) {
      if (edge?.node) pushFeed('taxii-push', edge.node);
    }
    for (const edge of feedsData?.ingestionCsvs?.edges ?? []) {
      if (edge?.node) pushFeed('csv', edge.node);
    }
    for (const edge of feedsData?.ingestionJsons?.edges ?? []) {
      if (edge?.node) pushFeed('json', edge.node);
    }

    for (const edge of formsData?.forms?.edges ?? []) {
      if (!edge?.node) continue;
      const node = edge.node;
      items.push({
        id: node.id,
        kind: 'form',
        sectionKey: 'form',
        name: node.name,
        description: node.description,
        ...feedStatus(node.active),
        running: !!node.active,
        messagesCount: feedQueueMessages(node.id),
        lastRunDate: null,
        updatedAt: (node.updated_at as string | null) ?? null,
        isManaged: false,
        detailUrl: `/dashboard/integrations/feeds/form/${node.id}`,
        searchText: buildSearchText([node.name, node.description, builtInLabel('form')]),
      });
    }

    return items;
  }, [connectorsListData, connectorsStateData, feedsData, formsData, logosBySlug]);
};

export default useDeployedIntegrations;
