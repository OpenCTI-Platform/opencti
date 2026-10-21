import conf, { logApp } from '../../config/conf';
import { isNotEmptyField } from '../../database/utils';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixObject } from '../../types/stix-2-1-common';
import { type GetHttpClient, getHttpClient, OpenCTIHeaders } from '../../utils/http-client';
import { now, utcDate } from '../../utils/format';
import { IngestionAuthType } from '../../generated/graphql';
import type { StixIndicator } from '../indicator/indicator-types';
import type { BasicStoreEntityIngestionTaxii, BasicStoreEntityIngestionTaxiiCollection } from './ingestion-types';
import type { TaxiiIngestionPatch } from './ingestion-taxii-domain';
import { decryptIngestionCredential, FEED_REQUEST_TIMEOUT } from './ingestion-common';

const INGESTION_MANAGER_TAXII_FEED_LIMIT_PER_REQUEST = conf.get('ingestion_manager:taxii_feed:limit_per_request') || 0;

export interface TaxiiResponseData {
  data: { more: boolean | undefined; next: string | undefined; objects: StixObject[] };
  addedLastHeader: string | undefined | null;
}

interface TaxiiGetParams {
  next: string | undefined;
  added_after: string | undefined;
  limit?: string | undefined;
}

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

export const buildTaxiiHttpClientOptions = async (ingestion: BasicStoreEntityIngestionTaxii) => {
  const octiHeaders = new OpenCTIHeaders();
  octiHeaders.Accept = 'application/taxii+json;version=2.1';

  const decryptedAuthValue = await decryptIngestionCredential(ingestion.authentication_value) ?? '';

  if (ingestion.authentication_type === IngestionAuthType.Basic) {
    const auth = Buffer.from(decryptedAuthValue, 'utf-8').toString('base64');
    octiHeaders.Authorization = `Basic ${auth}`;
  }
  if (ingestion.authentication_type === IngestionAuthType.Bearer) {
    octiHeaders.Authorization = `Bearer ${decryptedAuthValue}`;
  }
  let certificates;
  if (ingestion.authentication_type === IngestionAuthType.Certificate) {
    certificates = { cert: decryptedAuthValue.split(':')[0], key: decryptedAuthValue.split(':')[1], ca: decryptedAuthValue.split(':')[2] };
  }

  const httpClientOptions: GetHttpClient = {
    headers: octiHeaders,
    rejectUnauthorized: ingestion.ssl_verify ?? false,
    timeout: FEED_REQUEST_TIMEOUT,
    responseType: 'json',
    certificates,
  };
  return httpClientOptions;
};

export const taxiiHttpGet = async (ingestion: BasicStoreEntityIngestionTaxii): Promise<TaxiiResponseData> => {
  const httpClientOptions = await buildTaxiiHttpClientOptions(ingestion);
  const httpClient = getHttpClient(httpClientOptions);
  const preparedUri = ingestion.uri.endsWith('/') ? ingestion.uri : `${ingestion.uri}/`;
  const url = `${preparedUri}collections/${ingestion.collection}/objects/`;
  const params = prepareTaxiiGetParam(ingestion);

  logApp.info('[OPENCTI-MODULE] Taxii HTTP sending', {
    ingestion: ingestion.name,
    request: {
      params,
      url,
    },
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

/**
 * Computes the feed state to save after a TAXII response, so the next request resumes at the right place.
 * - Objects received and the server announces a next page: keep paginating with its cursor, `added_after_start` untouched.
 * - Objects received and no next page: reset the cursor and move `added_after_start` to the server's
 *   X-TAXII-Date-Added-Last header (or now when the server does not send it).
 * - No object received: reset the cursor only.
 */
export const computeTaxiiNextState = ({ data, addedLastHeader }: TaxiiResponseData): TaxiiIngestionPatch => {
  if (data.objects && data.objects.length > 0) {
    if (data.more && isNotEmptyField(data.next)) {
      return { current_state_cursor: data.next, last_execution_date: now() };
    }
    return {
      current_state_cursor: undefined,
      added_after_start: addedLastHeader ? utcDate(addedLastHeader).toISOString() : now(),
      last_execution_date: now(),
    };
  }
  return { last_execution_date: now(), current_state_cursor: undefined };
};

/**
 * When the feed has `confidence_to_score` enabled, copies each indicator's confidence
 * into its OpenCTI score extension. Other objects are returned unchanged.
 * Shared by the TAXII feeds (pulled by the ingestion manager) and the TAXII push collections.
 */
export const handleConfidenceToScoreTransformation = (ingestion: BasicStoreEntityIngestionTaxii | BasicStoreEntityIngestionTaxiiCollection, objects: StixObject[]) => {
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
