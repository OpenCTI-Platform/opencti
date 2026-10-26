import { describe, expect, it, vi } from 'vitest';
import {
  buildTaxiiHttpClientOptions,
  computeTaxiiNextState,
  handleConfidenceToScoreTransformation,
  prepareTaxiiGetParam,
  type TaxiiResponseData,
  taxiiHttpGet,
} from '../../../../src/modules/ingestion/ingestion-taxii-utils';
import { FEED_REQUEST_TIMEOUT } from '../../../../src/modules/ingestion/ingestion-common';
import type { BasicStoreEntityIngestionTaxii } from '../../../../src/modules/ingestion/ingestion-types';
import { IngestionAuthType } from '../../../../src/generated/graphql';
import { getHttpClient } from '../../../../src/utils/http-client';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { StixObject } from '../../../../src/types/stix-2-1-common';

vi.mock('../../../../src/utils/http-client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/utils/http-client')>();
  return { ...original, getHttpClient: vi.fn() };
});

// Credentials are stored encrypted; the tests only care about how the clear value is used
vi.mock('../../../../src/modules/ingestion/ingestion-common', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/modules/ingestion/ingestion-common')>();
  return { ...original, decryptIngestionCredential: vi.fn(async (value) => value) };
});

const buildIngestion = (overrides: Partial<BasicStoreEntityIngestionTaxii> = {}) => ({
  name: 'My taxii feed',
  uri: 'https://taxii.example.com/api',
  collection: 'collection-id',
  current_state_cursor: undefined,
  added_after_start: undefined,
  authentication_type: IngestionAuthType.None,
  authentication_value: undefined,
  confidence_to_score: false,
  ...overrides,
} as unknown as BasicStoreEntityIngestionTaxii);

const indicator = (props: Record<string, unknown> = {}) => ({
  type: 'indicator', id: 'indicator--1', confidence: 80, ...props,
} as unknown as StixObject);

const response = (data: Partial<TaxiiResponseData['data']>, addedLastHeader?: string | null): TaxiiResponseData => ({
  data: { more: undefined, next: undefined, objects: [], ...data },
  addedLastHeader,
});

describe('ingestion-taxii-utils', () => {
  describe('handleConfidenceToScoreTransformation', () => {
    it('should return the objects untouched when the feed does not convert confidence to score', () => {
      const objects = [indicator()];
      expect(handleConfidenceToScoreTransformation(buildIngestion(), objects)).toBe(objects);
    });

    it('should create the OpenCTI extension with the score when the indicator has no extension', () => {
      const [result] = handleConfidenceToScoreTransformation(buildIngestion({ confidence_to_score: true }), [indicator()]);
      expect(result.extensions).toEqual({ [STIX_EXT_OCTI]: { score: 80 } });
    });

    it('should add the OpenCTI extension next to existing ones', () => {
      const [result] = handleConfidenceToScoreTransformation(
        buildIngestion({ confidence_to_score: true }),
        [indicator({ extensions: { 'other-extension': { foo: 'bar' } } })],
      );
      expect(result.extensions).toEqual({ 'other-extension': { foo: 'bar' }, [STIX_EXT_OCTI]: { score: 80 } });
    });

    it('should overwrite the score of an existing OpenCTI extension', () => {
      const [result] = handleConfidenceToScoreTransformation(
        buildIngestion({ confidence_to_score: true }),
        [indicator({ extensions: { [STIX_EXT_OCTI]: { score: 10, detection: true } } })],
      );
      expect(result.extensions).toEqual({ [STIX_EXT_OCTI]: { score: 80, detection: true } });
    });

    it('should leave other objects and indicators without confidence untouched', () => {
      const report = { type: 'report', id: 'report--1', confidence: 50 } as unknown as StixObject;
      const noConfidence = indicator({ confidence: undefined });
      const result = handleConfidenceToScoreTransformation(buildIngestion({ confidence_to_score: true }), [report, noConfidence]);
      expect(result[0]).not.toHaveProperty('extensions');
      expect(result[1]).not.toHaveProperty('extensions');
    });
  });

  describe('prepareTaxiiGetParam', () => {
    it('should resume from the saved cursor and start date, without a page limit by default', () => {
      const params = prepareTaxiiGetParam(buildIngestion({ current_state_cursor: 'cursor-1', added_after_start: '2024-01-01T00:00:00.000Z' }));
      expect(params).toEqual({ next: 'cursor-1', added_after: '2024-01-01T00:00:00.000Z' });
    });
  });

  describe('buildTaxiiHttpClientOptions', () => {
    it('should request TAXII 2.1 json with the feed timeout and no authentication', async () => {
      const options = await buildTaxiiHttpClientOptions(buildIngestion());
      expect(options).toMatchObject({ responseType: 'json', timeout: FEED_REQUEST_TIMEOUT, rejectUnauthorized: undefined, certificates: undefined });
      expect(options.headers).toMatchObject({ Accept: 'application/taxii+json;version=2.1' });
      expect(options.headers).not.toHaveProperty('Authorization');
    });

    it('should send basic credentials base64-encoded', async () => {
      const options = await buildTaxiiHttpClientOptions(buildIngestion({ authentication_type: IngestionAuthType.Basic, authentication_value: 'user:password' }));
      expect(options.headers).toMatchObject({ Authorization: `Basic ${Buffer.from('user:password').toString('base64')}` });
    });

    it('should send a bearer token', async () => {
      const options = await buildTaxiiHttpClientOptions(buildIngestion({ authentication_type: IngestionAuthType.Bearer, authentication_value: 'token' }));
      expect(options.headers).toMatchObject({ Authorization: 'Bearer token' });
    });

    it('should split a client certificate into cert, key and ca', async () => {
      const options = await buildTaxiiHttpClientOptions(buildIngestion({ authentication_type: IngestionAuthType.Certificate, authentication_value: 'cert:key:ca' }));
      expect(options.certificates).toEqual({ cert: 'cert', key: 'key', ca: 'ca' });
      expect(options.headers).not.toHaveProperty('Authorization');
    });

    it('should verify SSL only when the feed asks for it', async () => {
      expect((await buildTaxiiHttpClientOptions(buildIngestion({ ssl_verify: true }))).rejectUnauthorized).toBe(true);
    });
  });

  describe('taxiiHttpGet', () => {
    const mockGet = (result: unknown) => {
      const get = vi.fn().mockResolvedValue(result);
      vi.mocked(getHttpClient).mockReturnValue({ get } as unknown as ReturnType<typeof getHttpClient>);
      return get;
    };

    it('should get the collection objects with the pagination params and return the added-last header', async () => {
      const data = { more: true, next: 'cursor-2', objects: [indicator()] };
      const get = mockGet({ data, headers: { 'x-taxii-date-added-last': '2024-01-02T00:00:00.000Z' }, status: 200 });

      const result = await taxiiHttpGet(buildIngestion({ current_state_cursor: 'cursor-1' }));

      expect(get).toHaveBeenCalledWith(
        'https://taxii.example.com/api/collections/collection-id/objects/',
        { params: { next: 'cursor-1', added_after: undefined } },
      );
      expect(result).toEqual({ data, addedLastHeader: '2024-01-02T00:00:00.000Z' });
    });

    it('should not double the slash when the feed uri already ends with one', async () => {
      const get = mockGet({ data: { objects: [] }, headers: {}, status: 200 });
      await taxiiHttpGet(buildIngestion({ uri: 'https://taxii.example.com/api/' }));
      expect(get.mock.calls[0][0]).toBe('https://taxii.example.com/api/collections/collection-id/objects/');
    });
  });

  describe('computeTaxiiNextState', () => {
    it('should keep paginating with the server cursor, without touching the start date', () => {
      const state = computeTaxiiNextState(response({ objects: [indicator()], more: true, next: 'cursor-2' }, '2024-01-02T00:00:00.000Z'));
      expect(state).toEqual({ current_state_cursor: 'cursor-2', last_execution_date: expect.any(String) });
    });

    it('should reset the cursor and restart after the last added date at the end of the pages', () => {
      const state = computeTaxiiNextState(response({ objects: [indicator()], more: false }, '2024-01-02T10:00:00Z'));
      expect(state).toEqual({ current_state_cursor: undefined, added_after_start: '2024-01-02T10:00:00.000Z', last_execution_date: expect.any(String) });
    });

    it('should not paginate when the server says there is more but sends no cursor', () => {
      const state = computeTaxiiNextState(response({ objects: [indicator()], more: true, next: undefined }, '2024-01-02T10:00:00Z'));
      expect(state.current_state_cursor).toBeUndefined();
      expect(state.added_after_start).toBe('2024-01-02T10:00:00.000Z');
    });

    it('should restart from now when the server sends no added-last header', () => {
      const before = Date.now();
      const state = computeTaxiiNextState(response({ objects: [indicator()] }, undefined));
      expect(new Date(state.added_after_start!).getTime()).toBeGreaterThanOrEqual(before - 1000);
    });

    it('should only reset the cursor when no object is received', () => {
      const state = computeTaxiiNextState(response({ objects: [], more: true, next: 'cursor-2' }, '2024-01-02T10:00:00Z'));
      expect(state).toEqual({ current_state_cursor: undefined, last_execution_date: expect.any(String) });
    });
  });
});
