import { AxiosError } from 'axios';
import type { AuthContext } from '../../types/user';
import { connectorIdFromIngestId } from '../../domain/connector';
import conf from '../../config/conf';
import { patchAttribute } from '../../database/middleware';
import { SYSTEM_USER } from '../../utils/access';
import { isDateInRange, now, nowTime, schedulingPeriodToMs, utcDate } from '../../utils/format';
import { isNotEmptyField } from '../../database/utils';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import type {
  BasicStoreEntityIngestionCsv,
  BasicStoreEntityIngestionJson,
  BasicStoreEntityIngestionRss,
  BasicStoreEntityIngestionTaxii,
  BasicStoreEntityIngestionTaxiiCollection
} from '../../modules/ingestion/ingestion-types';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { ConnectorType } from '../../generated/graphql';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import type { StixIndicator } from '../../modules/indicator/indicator-types';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 30000;

export type IngestionTypes = BasicStoreEntityIngestionTaxii
| BasicStoreEntityIngestionRss | BasicStoreEntityIngestionCsv | BasicStoreEntityIngestionTaxiiCollection | BasicStoreEntityIngestionJson;

export const asArray = (data: unknown) => {
  if (data) {
    if (Array.isArray(data)) {
      return data;
    }
    return [data];
  }
  return [];
};

export const isMustExecuteIteration = (last_execution_date: Date | undefined, scheduling_period: string) => {
  if (isNotEmptyField(scheduling_period) && scheduling_period !== 'auto' && last_execution_date) {
    const schedulingPeriod = schedulingPeriodToMs(scheduling_period);
    const isInRange = isDateInRange(last_execution_date, schedulingPeriod, utcDate());
    return !isInRange;
  }
  return true;
};

interface UpdateInfo {
  state?: any
  buffering?: boolean
  messages_size?: number
}
export const updateBuiltInConnectorInfo = async (context: AuthContext, user_id: string | undefined, id: string, opts: UpdateInfo = {}) => {
  // Patch the related connector
  const csvNow = utcDate();
  const connectorPatch: any = {
    updated_at: csvNow.toISOString(),
    connector_info: {
      last_run_datetime: csvNow.toISOString(),
      next_run_datetime: csvNow.add(SCHEDULE_TIME, 'milliseconds').toISOString(),
      run_and_terminate: false,
      buffering: opts.buffering ?? false,
      queue_threshold: 0,
      queue_messages_size: (opts.messages_size ?? 0) / 1000000 // In Mb
    },
    connector_user_id: user_id,
  };
  if (opts.state) {
    connectorPatch.connector_state = JSON.stringify(opts.state);
  }
  const connectorId = connectorIdFromIngestId(id);
  await patchAttribute(context, SYSTEM_USER, connectorId, ENTITY_TYPE_CONNECTOR, connectorPatch);
};

export const createWorkForIngestion = async (context: AuthContext, ingestion: IngestionTypes) => {
  const connector = { internal_id: connectorIdFromIngestId(ingestion.id), connector_type: ConnectorType.ExternalImport };
  const workName = `run @ ${now()}`;
  const work: any = await createWork(context, SYSTEM_USER, connector, workName, connector.internal_id, { receivedTime: now() });
  return work;
};

export const pushBundleToConnectorQueue = async (context: AuthContext, ingestion: IngestionTypes, bundle: StixBundle) => {
  // Push the bundle to absorption queue
  const connectorId = connectorIdFromIngestId(ingestion.id);
  const work: any = await createWorkForIngestion(context, ingestion);
  const stixBundle = JSON.stringify(bundle);
  const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
  if (bundle.objects.length === 1) {
    // Only add explicit expectation if the worker will not split anything
    await updateExpectationsNumber(context, SYSTEM_USER, work.id, bundle.objects.length);
  }
  await pushToWorkerForConnector(connectorId, {
    type: 'bundle',
    applicant_id: ingestion.user_id ?? OPENCTI_SYSTEM_UUID,
    content,
    work_id: work.id,
    update: true
  });
  return work.id;
};

export const handleConfidenceToScoreTransformation = (ingestion: BasicStoreEntityIngestionTaxii | BasicStoreEntityIngestionTaxiiCollection, objects: StixObject[]) => {
  // noinspection PointlessBooleanExpressionJS
  if (ingestion.confidence_to_score === true) {
    return objects.map((o) => {
      if (o.type === 'indicator') {
        const indicator = o as StixIndicator;
        if (isNotEmptyField(indicator.confidence)) {
          if (indicator.extensions && indicator.extensions[STIX_EXT_OCTI]) {
            indicator.extensions[STIX_EXT_OCTI].score = indicator.confidence;
          } else if (indicator.extensions) {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            indicator.extensions[STIX_EXT_OCTI] = { score: indicator.confidence };
          } else {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            indicator.extensions = { [STIX_EXT_OCTI]: { score: indicator.confidence } };
          }
          return indicator;
        }
      }
      return o;
    });
  }
  return objects;
};

export const buildIngestFailureMessages = (e: Error) => {
  const messages = [];
  if (e instanceof AxiosError) {
    messages.push(`${e.code} fetching feed / ${nowTime()}`);
    if (e.response) {
      messages.push(`Status: ${e.response.status} - ${e.response.statusText}`);
      if (isNotEmptyField(e.response.data)) {
        const responseData: string = JSON.stringify(e.response.data, null, 2);
        const isTooLargeResponse = responseData.length > 1000;
        messages.push(`Content: ${responseData.substring(0, 1000)}${isTooLargeResponse ? '...' : ''}`);
      }
      if (e.response.headers['cf-mitigated']) {
        messages.push('Analysis: Cloudflare challenge fail');
      }
    }
  } else {
    messages.push(`Error fetching feed / ${nowTime()}`);
    messages.push(`Content: ${e.name} - ${e.message}`);
  }
  return messages;
};

export const buildIngestQueueControlMessages = () => {
  return [`Feed in waiting mode at ${now()}, consuming existing fetched information`];
};

export const buildIngestSuccessMessages = (size: number) => {
  return [`Success fetching feed at ${now()}`, `${size} elements sent to ingestion`];
};
