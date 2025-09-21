import { v4 as uuidv4 } from 'uuid';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntityIngestionTaxii } from '../../modules/ingestion/ingestion-types';
import { getHttpClient, type GetHttpClient, OpenCTIHeaders } from '../../utils/http-client';
import { IngestionAuthType, TaxiiVersion } from '../../generated/graphql';
import conf, { logApp } from '../../config/conf';
import type { AuthContext } from '../../types/user';
import { isNotEmptyField } from '../../database/utils';
import { now, utcDate } from '../../utils/format';
import { findAllTaxiiIngestion } from '../../modules/ingestion/ingestion-taxii-domain';
import { SYSTEM_USER } from '../../utils/access';
import { UnsupportedError } from '../../config/errors';
import { handleConfidenceToScoreTransformation, pushBundleToConnectorQueue } from './ingestionUtils';
import { ingestionQueueExecution } from './ingestionExecutor';

const INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST = conf.get('ingestion_manager:taxii_feed:limit_per_request') || 0;

// region Types
export interface TaxiiResponseData {
  data: { more: boolean | undefined, next: string | undefined, objects: StixObject[] },
  addedLastHeader: string | undefined | null
}
interface TaxiiGetParams {
  next: string | undefined,
  added_after: Date | undefined,
  limit?: string | undefined
}
type TaxiiConnectorState = { current_state_cursor?: string, added_after_start?: string };
type TaxiiIngestionPatch = TaxiiConnectorState & { last_execution_date: string };
type TaxiiConnectorInfo = { state?: TaxiiConnectorState };
type HandlerResponse = { size: number, ingestionPatch: TaxiiIngestionPatch, connectorInfo: TaxiiConnectorInfo };
type TaxiiHandlerFn = (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii, taxiResponse:TaxiiResponseData) => Promise<HandlerResponse>;
// endregion Types

/**
 *  Compute HTTP GET parameters to send to taxii server.
 *
 *  @see https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107519
 *   // If the more property is set to true and the next property is populated
 *   // then the client can paginate through the remaining records
 *   // using the next URL parameter along with the same original query options.
 *   // If the more property is set to true and the next property is empty
 *   // then the client may paginate through the remaining records by using the added_after URL parameter with the
 *   // date/time value from the X-TAXII-Date-Added-Last header along with the same original query options.
 * @param ingestion
 */
export const prepareTaxiiGetParam = (ingestion: BasicStoreEntityIngestionTaxii) => {
  const params: TaxiiGetParams = { next: ingestion.current_state_cursor, added_after: ingestion.added_after_start };
  if (INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST > 0) {
    params.limit = INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST;
  }
  return params;
};

const taxiiHttpGet = async (ingestion: BasicStoreEntityIngestionTaxii): Promise<TaxiiResponseData> => {
  const octiHeaders = new OpenCTIHeaders();
  octiHeaders.Accept = 'application/taxii+json;version=2.1';
  if (ingestion.authentication_type === IngestionAuthType.Basic) {
    const auth = Buffer.from(ingestion.authentication_value, 'utf-8').toString('base64');
    octiHeaders.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Bearer) {
    octiHeaders.Authorization = `Bearer ${ingestion.authentication_value}`;
  }
  let certificates;
  if (ingestion.authentication_type === IngestionAuthType.Certificate) {
    certificates = { cert: ingestion.authentication_value.split(':')[0], key: ingestion.authentication_value.split(':')[1], ca: ingestion.authentication_value.split(':')[2] };
  }

  const httpClientOptions: GetHttpClient = { headers: octiHeaders, rejectUnauthorized: false, responseType: 'json', certificates };
  const httpClient = getHttpClient(httpClientOptions);
  const preparedUri = ingestion.uri.endsWith('/') ? ingestion.uri : `${ingestion.uri}/`;
  const url = `${preparedUri}collections/${ingestion.collection}/objects/`;
  const params = prepareTaxiiGetParam(ingestion);
  logApp.info('[OPENCTI-MODULE] Taxii HTTP sending', {
    ingestion: ingestion.name,
    request: {
      params,
      url,
    }
  });
  const { data, headers, status } = await httpClient.get(url, { params });
  logApp.info('[OPENCTI-MODULE] Taxii HTTP Get done.', {
    ingestion: ingestion.name,
    response: {
      addedLastHeader: headers['x-taxii-date-added-last'],
      addedFirstHeader: headers['x-taxii-date-added-first'],
      more: data.more,
      next: data.next,
      status,
    },
  });
  return { data, addedLastHeader: headers['x-taxii-date-added-last'] };
};

export const processTaxiiResponse: TaxiiHandlerFn = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii, taxiResponse:TaxiiResponseData) => {
  const { data, addedLastHeader } = taxiResponse;
  if (data.objects && data.objects.length > 0) {
    logApp.info(`[OPENCTI-MODULE] Taxii ingestion execution for ${data.objects.length} items, sending stix bundle to workers.`, { ingestionId: ingestion.id });
    const objects = handleConfidenceToScoreTransformation(ingestion, data.objects);
    const bundle: StixBundle = { type: 'bundle', spec_version: '2.1', id: `bundle--${uuidv4()}`, objects };
    // Push the bundle to absorption queue
    await pushBundleToConnectorQueue(context, ingestion, bundle);
    const more = data.more || false;
    // Update the state
    if (more && isNotEmptyField(data.next)) {
      // Do not touch to added_after_start
      const ingestionPatch = { current_state_cursor: data.next, last_execution_date: now() };
      const connectorState = { current_state_cursor: data.next, added_after_start: ingestion.added_after_start?.toISOString() };
      return { size: data.objects.length, ingestionPatch, connectorInfo: { state: connectorState } };
    }
    // Reset the pagination cursor, and update date
    const ingestionPatch = {
      current_state_cursor: undefined,
      added_after_start: addedLastHeader ? utcDate(addedLastHeader).toISOString() : now(),
      last_execution_date: now()
    };
    return { size: data.objects.length, ingestionPatch, connectorInfo: {} };
  }
  logApp.info('[OPENCTI-MODULE] Taxii ingestion - taxii server has not sent any object.', {
    next: data.next,
    more: data.more,
    addedLastHeader,
    ingestionId: ingestion.id,
    ingestionName: ingestion.name
  });
  return { size: 0, ingestionPatch: { last_execution_date: now() }, connectorInfo: {} };
};

const taxiiV21DataHandler = async (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => {
  const taxiResponse = await taxiiHttpGet(ingestion);
  return processTaxiiResponse(context, ingestion, taxiResponse);
};
const TAXII_HANDLERS: { [k: string]: (context: AuthContext, ingestion: BasicStoreEntityIngestionTaxii) => Promise<HandlerResponse> } = {
  [TaxiiVersion.V21]: taxiiV21DataHandler
};

export const taxiiExecutor = async (context: AuthContext) => {
  const filters = {
    mode: 'and',
    filters: [{ key: 'ingestion_running', values: [true] }],
    filterGroups: [],
  };
  const opts = { filters, noFiltersChecking: true };
  const ingestions = await findAllTaxiiIngestion(context, SYSTEM_USER, opts);
  const ingestionPromises = [];
  for (let i = 0; i < ingestions.length; i += 1) {
    const ingestion = ingestions[i];
    const taxiiHandler = TAXII_HANDLERS[ingestion.version];
    if (!taxiiHandler) {
      throw UnsupportedError(`[OPENCTI-MODULE] Taxii version ${ingestion.version} is not yet supported`);
    }
    const dataHandlerFn = () => taxiiHandler(context, ingestion);
    ingestionPromises.push(ingestionQueueExecution(context, ingestion, dataHandlerFn));
  }
  return Promise.all(ingestionPromises);
};
