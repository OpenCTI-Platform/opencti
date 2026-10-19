import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockPost } = vi.hoisted(() => ({ mockPost: vi.fn() }));

vi.mock('../../../../../src/config/conf', () => ({
  default: { get: vi.fn(() => 'http://hub.test') },
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
  PLATFORM_VERSION: '7.0.0-test',
  getPlatformHttpProxyAgent: vi.fn(() => undefined),
}));

vi.mock('../../../../../src/database/utils', () => ({
  fromBase64: vi.fn(),
  isNotEmptyField: vi.fn(() => false),
}));

vi.mock('../../../../../src/utils/http-client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/utils/http-client')>()),
  getHttpClient: vi.fn(() => ({ post: mockPost })),
}));

const PLATFORM_ID = 'platform-id';
const TOKEN = 'platform-token';
const PLATFORM_VERSION = '7.0.0';
const BASE_INPUT = { platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformIdentifier: 'opencti' };
const FALLBACK_LOG = '[XTMH] XTM Hub does not accept the platform edition yet, refreshing the connectivity without it';
const ECHOED_INPUT = '{ platformId: "platform-id", token: "platform-token", platformVersion: "7.0.0", platformIdentifier: "opencti", platformContract: "EE" }';
const UNKNOWN_FIELD_ERROR = `Variable "$input" got invalid value ${ECHOED_INPUT}; `
  + 'Field "platformContract" is not defined by type "RefreshPlatformRegistrationConnectivityStatusInput".';
const OTHER_INPUT_ERROR = `Variable "$input" got invalid value ${ECHOED_INPUT}; Field "platformVersion" of required type "String!" was not provided.`;
const CONTRACT_UPDATE_ERROR = 'Unable to update the "platformContract" of the platform';

const statusResponse = (status: string) => ({ data: { data: { refreshPlatformRegistrationConnectivityStatus: { status } } } });
const graphqlErrorResponse = (message: string) => ({ data: { data: null, errors: [{ message }] } });
const { HttpClientError } = await import('../../../../../src/utils/http-client');
const badRequestError = (message: string) => new HttpClientError('Request failed with status code 400', 'ERR_BAD_REQUEST', {
  status: 400,
  statusText: 'Bad Request',
  headers: {},
  data: { errors: [{ message, extensions: { code: 'BAD_USER_INPUT' } }] },
});

const loadClient = async () => {
  const { xtmHubClient } = await import('../../../../../src/modules/xtm/hub/xtm-hub-client');
  const { logApp } = await import('../../../../../src/config/conf');
  return { xtmHubClient, logApp };
};

const sentInputs = () => mockPost.mock.calls.map(([, body]) => body.variables.input);

describe('xtmHubClient.refreshRegistrationStatus', () => {
  beforeEach(() => {
    vi.resetModules();
    mockPost.mockReset();
  });

  it('should send the platform edition when the hub accepts it', async () => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost.mockResolvedValueOnce(statusResponse('active'));

    // When
    const status = await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'EE' });

    // Then
    expect({ status, inputs: sentInputs() }).toEqual({ status: 'active', inputs: [{ ...BASE_INPUT, platformContract: 'EE' }] });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(UNKNOWN_FIELD_ERROR)) },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(UNKNOWN_FIELD_ERROR)) },
  ])('should retry without the edition when the hub rejects the field with $rejection', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockRejection();
    mockPost.mockResolvedValueOnce(statusResponse('active'));

    // When
    const status = await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'CE' });

    // Then
    expect({ status, inputs: sentInputs() }).toEqual({ status: 'active', inputs: [{ ...BASE_INPUT, platformContract: 'CE' }, BASE_INPUT] });
  });

  it('should log the fallback once when the hub keeps rejecting the edition', async () => {
    // Given
    const { xtmHubClient, logApp } = await loadClient();
    mockPost
      .mockRejectedValueOnce(badRequestError(UNKNOWN_FIELD_ERROR))
      .mockResolvedValueOnce(statusResponse('active'))
      .mockRejectedValueOnce(badRequestError(UNKNOWN_FIELD_ERROR))
      .mockResolvedValueOnce(statusResponse('active'));

    // When
    await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'EE' });
    await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'EE' });

    // Then
    expect(vi.mocked(logApp.warn).mock.calls.filter(([message]) => message === FALLBACK_LOG)).toHaveLength(1);
  });

  it.each([
    { reason: 'another input error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(OTHER_INPUT_ERROR)) },
    { reason: 'an error naming the edition field', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(CONTRACT_UPDATE_ERROR)) },
  ])('should return inactive without retrying when the hub rejects the refresh with $reason', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockRejection();

    // When
    const status = await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'EE' });

    // Then
    expect({ status, calls: mockPost.mock.calls.length }).toEqual({ status: 'inactive', calls: 1 });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(OTHER_INPUT_ERROR)), codes: ['BAD_USER_INPUT'] },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(OTHER_INPUT_ERROR)), codes: [] },
  ])('should log the error codes but not the echoed token when the hub rejects the refresh with $rejection', async ({ mockRejection, codes }) => {
    // Given
    const { xtmHubClient, logApp } = await loadClient();
    mockRejection();

    // When
    await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'EE' });

    // Then
    expect(vi.mocked(logApp.warn).mock.calls).toEqual([['XTM Hub sent an error', { codes }]]);
  });

  it('should return inactive when the hub is unreachable', async () => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost.mockRejectedValueOnce(new HttpClientError('connect ECONNREFUSED', 'ECONNREFUSED'));

    // When
    const status = await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformContract: 'EE' });

    // Then
    expect({ status, calls: mockPost.mock.calls.length }).toEqual({ status: 'inactive', calls: 1 });
  });
});
