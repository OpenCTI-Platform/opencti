import type { AuthContext } from '../../types/user';
import type {
  BasicStoreEntityIngestionCsv,
  BasicStoreEntityIngestionJson,
  BasicStoreEntityIngestionRss,
  BasicStoreEntityIngestionTaxii,
  BasicStoreEntityIngestionTaxiiCollection,
} from '../../modules/ingestion/ingestion-types';
import { connectorIdFromIngestId } from '../../domain/connector';
import { ConnectorType } from '../../generated/graphql';
import { now, utcDate } from '../../utils/format';
import { createWork } from '../../domain/work';
import { SYSTEM_USER } from '../../utils/access';
import { patchAttribute } from '../../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import type { StixBundle } from '../../types/stix-2-1-common';
import { pushBundleToWorker } from '../../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { INGESTION_MANAGER_SCHEDULE_TIME } from './ingestionManagerConfiguration';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../../database/cache';
import { logApp } from '../../config/conf';
import { type BasicStoreEntitySource, ENTITY_TYPE_SOURCE, SOURCE_KIND_INGESTION_FEED } from '../../modules/sourceIntelligence/sourceIntelligence-types';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE } from '../../modules/draftWorkspace/draftWorkspace-types';
import { DRAFT_STATUS_OPEN } from '../../modules/draftWorkspace/draftStatuses';

/**
 * All utilities for ingestion manager that push bundle to queues
 */

interface UpdateInfo {
  state?: any;
  buffering?: boolean;
  messages_size?: number;
}

export const updateBuiltInConnectorInfo = async (context: AuthContext, user_id: string | undefined, id: string, opts: UpdateInfo = {}) => {
  // Patch the related connector
  const csvNow = utcDate();
  const connectorPatch: any = {
    updated_at: csvNow.toISOString(),
    connector_info: {
      last_run_datetime: csvNow.toISOString(),
      next_run_datetime: csvNow.add(INGESTION_MANAGER_SCHEDULE_TIME, 'milliseconds').toISOString(),
      run_and_terminate: false,
      buffering: opts.buffering ?? false,
      queue_threshold: 0,
      queue_messages_size: (opts.messages_size ?? 0) / 1000000, // In Mb
    },
    connector_user_id: user_id,
  };
  if (opts.state) {
    connectorPatch.connector_state = JSON.stringify(opts.state);
  }
  const connectorId = connectorIdFromIngestId(id);
  await patchAttribute(context, SYSTEM_USER, connectorId, ENTITY_TYPE_CONNECTOR, connectorPatch);
};
export const createWorkForIngestion = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii
  | BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionTaxiiCollection | BasicStoreEntityIngestionJson) => {
  const connector = {
    internal_id: connectorIdFromIngestId(ingestion.id),
    connector_type: ConnectorType.ExternalImport,
  };
  const workName = `run @ ${now()}`;
  const work: any = await createWork(context, SYSTEM_USER, connector, workName, connector.internal_id, { receivedTime: now() });
  return work;
};
/**
 * Draft receiving the data of a feed quarantined by Source Intelligence, if the quarantine draft is still open.
 */
export const resolveQuarantineDraftId = async (context: AuthContext, ingestionId: string): Promise<string | undefined> => {
  const sources = await getEntitiesListFromCache<BasicStoreEntitySource>(context, SYSTEM_USER, ENTITY_TYPE_SOURCE);
  const source = sources.find((s) => s.source_kind === SOURCE_KIND_INGESTION_FEED && s.ref_id === ingestionId);
  if (!source?.quarantined || !source.quarantine_draft_id) {
    return undefined;
  }
  const drafts = await getEntitiesMapFromCache<BasicStoreEntityDraftWorkspace>(context, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
  const draft = drafts.get(source.quarantine_draft_id);
  if (!draft || draft.draft_status !== DRAFT_STATUS_OPEN) {
    logApp.warn('[OPENCTI-MODULE] Quarantine draft of the feed is not open anymore, data is ingested in the live knowledge', { ingestionId, draftId: source.quarantine_draft_id });
    return undefined;
  }
  return draft.id;
};

export const pushBundleToConnectorQueue = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii
  | BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionTaxiiCollection | BasicStoreEntityIngestionJson, bundle: StixBundle) => {
  // Push the bundle to absorption queue
  const connectorId = connectorIdFromIngestId(ingestion.id);
  const work: any = await createWorkForIngestion(context, ingestion);
  const stixBundle = JSON.stringify(bundle);
  const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
  const draftId = await resolveQuarantineDraftId(context, ingestion.id);
  await pushBundleToWorker(context, SYSTEM_USER, connectorId, {
    type: 'bundle',
    applicant_id: ingestion.user_id ?? OPENCTI_SYSTEM_UUID,
    content,
    work_id: work.id,
    update: true,
    ...(draftId ? { draft_id: draftId } : {}),
  });
  return work.id;
};
