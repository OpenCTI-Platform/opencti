import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockPost } = vi.hoisted(() => ({ mockPost: vi.fn() }));

vi.mock('../../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/config/conf')>()),
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

// These calls carry the token: the key, and the calls signed with it, are covered by xtm-hub-client-credentials-test.
vi.mock('../../../../../src/modules/xtm/hub/xtm-hub-key', () => ({ getXtmHubKey: vi.fn() }));

const PLATFORM_ID = 'platform-id';
const TOKEN = 'platform-token';
const PLATFORM_VERSION = '7.0.0';
const TOKEN_CREDENTIALS = { kind: 'token' as const, token: TOKEN };
const REFRESH_INPUT = { platformId: PLATFORM_ID, credentials: TOKEN_CREDENTIALS, platformVersion: PLATFORM_VERSION, platformContract: 'EE' as const };
const ECHOED_INPUT = '{ platformId: "platform-id", token: "platform-token", platformVersion: "7.0.0", platformIdentifier: "opencti", platformContract: "EE" }';
const BASE_INPUT = { platformId: PLATFORM_ID, token: TOKEN, platformVersion: PLATFORM_VERSION, platformIdentifier: 'opencti' };
const INPUT_ERROR = `Variable "$input" got invalid value ${ECHOED_INPUT}; Field "platformVersion" of required type "String!" was not provided.`;
const UNKNOWN_CONTRACT_ERROR = `Variable "$input" got invalid value ${ECHOED_INPUT}; `
  + 'Field "platformContract" is not defined by type "RefreshPlatformRegistrationConnectivityStatusInput".';
const UNKNOWN_COMMERCIAL_MODEL_ERROR = 'Cannot query field "commercialModel" on type "PlatformRegistrationConnectivityStatus".';
const UNKNOWN_ORGANIZATION_NAME_ERROR = 'Cannot query field "organizationName" on type "RefreshPlatformRegistrationConnectivityStatusResponse".';
const CONTRACT_UPDATE_ERROR = 'Unable to update the "platformContract" of the platform';
const COMMERCIAL_MODEL_UPDATE_ERROR = 'Unable to compute the "commercialModel" of the platform';
const CONTRACT_FALLBACK_LOG = '[XTMH] XTM Hub does not accept the platform edition yet, refreshing the connectivity without it';
const COMMERCIAL_MODEL_FALLBACK_LOG = '[XTMH] XTM Hub does not expose the commercial model yet, refreshing the connectivity without it';
const ORGANIZATION_NAME_FALLBACK_LOG = '[XTMH] XTM Hub does not expose the organization name yet, refreshing the connectivity without it';

const refreshResponse = (refreshed: { status: string; commercialModel?: string | null; organizationName?: string | null }) => ({
  data: { data: { refreshPlatformRegistrationConnectivityStatus: refreshed } },
});
const graphqlErrorResponse = (...messages: string[]) => ({ data: { data: null, errors: messages.map((message) => ({ message })) } });
const { HttpClientError } = await import('../../../../../src/utils/http-client');
const badRequestError = (...messages: string[]) => new HttpClientError('Request failed with status code 400', 'ERR_BAD_REQUEST', {
  status: 400,
  statusText: 'Bad Request',
  headers: {},
  data: { errors: messages.map((message) => ({ message, extensions: { code: 'BAD_USER_INPUT' } })) },
});

const loadClient = async () => {
  const { xtmHubClient } = await import('../../../../../src/modules/xtm/hub/xtm-hub-client');
  const { logApp } = await import('../../../../../src/config/conf');
  return { xtmHubClient, logApp };
};

const sentRequests = () => mockPost.mock.calls.map(([, body]) => ({
  input: body.variables.input,
  asksCommercialModel: body.query.includes('commercialModel'),
  asksOrganizationName: body.query.includes('organizationName'),
}));

describe('xtmHubClient.refreshRegistrationStatus', () => {
  beforeEach(() => {
    vi.resetModules();
    mockPost.mockReset();
  });

  it('should send the platform edition and ask for the commercial model and the organization name', async () => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost.mockResolvedValueOnce(refreshResponse({ status: 'active', commercialModel: 'OTHER' }));

    // When
    await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    const [[, body]] = mockPost.mock.calls;
    expect(body.variables.input).toEqual({
      platformId: PLATFORM_ID,
      token: TOKEN,
      platformVersion: PLATFORM_VERSION,
      platformIdentifier: 'opencti',
      platformContract: 'EE',
    });
    expect(body.query).toContain('commercialModel');
    expect(body.query).toContain('organizationName');
  });

  it.each([
    { hubValue: 'SAAS', commercialModel: 'saas' },
    { hubValue: 'OTHER', commercialModel: 'other' },
    { hubValue: 'UNKNOWN_MODEL', commercialModel: null },
    { hubValue: null, commercialModel: null },
    { hubValue: undefined, commercialModel: null },
  ])('should return the commercial model $commercialModel when the hub answers $hubValue', async ({ hubValue, commercialModel }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost.mockResolvedValueOnce(refreshResponse({ status: 'active', commercialModel: hubValue }));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect(result).toEqual({ status: 'active', commercialModel, organizationName: null });
  });

  it.each([
    { hubValue: 'Filigran', organizationName: 'Filigran' },
    { hubValue: '  Filigran  ', organizationName: 'Filigran' },
    { hubValue: '   ', organizationName: null },
    { hubValue: null, organizationName: null },
    { hubValue: undefined, organizationName: null },
  ])('should return the organization name $organizationName when the hub answers $hubValue', async ({ hubValue, organizationName }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost.mockResolvedValueOnce(refreshResponse({ status: 'active', commercialModel: 'SAAS', organizationName: hubValue }));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect(result).toEqual({ status: 'active', commercialModel: 'saas', organizationName });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(UNKNOWN_CONTRACT_ERROR)) },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(UNKNOWN_CONTRACT_ERROR)) },
  ])('should retry without the edition when the hub rejects the field with $rejection', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockRejection();
    mockPost.mockResolvedValueOnce(refreshResponse({ status: 'active', commercialModel: 'SAAS', organizationName: 'Filigran' }));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus({ ...REFRESH_INPUT, platformContract: 'CE' });

    // Then
    expect({ result, requests: sentRequests() }).toEqual({
      result: { status: 'active', commercialModel: 'saas', organizationName: 'Filigran' },
      requests: [
        { input: { ...BASE_INPUT, platformContract: 'CE' }, asksCommercialModel: true, asksOrganizationName: true },
        { input: BASE_INPUT, asksCommercialModel: true, asksOrganizationName: true },
      ],
    });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(UNKNOWN_COMMERCIAL_MODEL_ERROR, UNKNOWN_ORGANIZATION_NAME_ERROR)) },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(UNKNOWN_COMMERCIAL_MODEL_ERROR, UNKNOWN_ORGANIZATION_NAME_ERROR)) },
  ])('should retry once without the commercial model nor the organization name but keep the edition when the hub rejects both fields with $rejection', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockRejection();
    mockPost.mockResolvedValueOnce(refreshResponse({ status: 'active' }));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect({ result, requests: sentRequests() }).toEqual({
      result: { status: 'active', commercialModel: null, organizationName: null },
      requests: [
        { input: { ...BASE_INPUT, platformContract: 'EE' }, asksCommercialModel: true, asksOrganizationName: true },
        { input: { ...BASE_INPUT, platformContract: 'EE' }, asksCommercialModel: false, asksOrganizationName: false },
      ],
    });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(UNKNOWN_ORGANIZATION_NAME_ERROR)) },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(UNKNOWN_ORGANIZATION_NAME_ERROR)) },
  ])('should retry without the organization name but keep the commercial model when the hub rejects the field with $rejection', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient, logApp } = await loadClient();
    mockRejection();
    mockPost.mockResolvedValueOnce(refreshResponse({ status: 'active', commercialModel: 'SAAS' }));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect({ result, requests: sentRequests(), logs: vi.mocked(logApp.warn).mock.calls }).toEqual({
      result: { status: 'active', commercialModel: 'saas', organizationName: null },
      requests: [
        { input: { ...BASE_INPUT, platformContract: 'EE' }, asksCommercialModel: true, asksOrganizationName: true },
        { input: { ...BASE_INPUT, platformContract: 'EE' }, asksCommercialModel: true, asksOrganizationName: false },
      ],
      logs: [[ORGANIZATION_NAME_FALLBACK_LOG]],
    });
  });

  it('should fall back to the legacy status-only refresh when the hub knows none of the fields', async () => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost
      .mockRejectedValueOnce(badRequestError(UNKNOWN_COMMERCIAL_MODEL_ERROR, UNKNOWN_ORGANIZATION_NAME_ERROR))
      .mockRejectedValueOnce(badRequestError(UNKNOWN_CONTRACT_ERROR))
      .mockResolvedValueOnce(refreshResponse({ status: 'active' }));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect({ result, requests: sentRequests() }).toEqual({
      result: { status: 'active', commercialModel: null, organizationName: null },
      requests: [
        { input: { ...BASE_INPUT, platformContract: 'EE' }, asksCommercialModel: true, asksOrganizationName: true },
        { input: { ...BASE_INPUT, platformContract: 'EE' }, asksCommercialModel: false, asksOrganizationName: false },
        { input: BASE_INPUT, asksCommercialModel: false, asksOrganizationName: false },
      ],
    });
  });

  it('should log each fallback once when the hub keeps rejecting the fields', async () => {
    // Given
    const { xtmHubClient, logApp } = await loadClient();
    const mockLegacyHubAnswers = () => mockPost
      .mockRejectedValueOnce(badRequestError(UNKNOWN_COMMERCIAL_MODEL_ERROR, UNKNOWN_ORGANIZATION_NAME_ERROR))
      .mockRejectedValueOnce(badRequestError(UNKNOWN_CONTRACT_ERROR))
      .mockResolvedValueOnce(refreshResponse({ status: 'active' }));
    mockLegacyHubAnswers();
    mockLegacyHubAnswers();

    // When
    await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);
    await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect(vi.mocked(logApp.warn).mock.calls).toEqual([[COMMERCIAL_MODEL_FALLBACK_LOG], [ORGANIZATION_NAME_FALLBACK_LOG], [CONTRACT_FALLBACK_LOG]]);
  });

  it.each([
    { reason: 'an error naming the edition field', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(CONTRACT_UPDATE_ERROR)) },
    { reason: 'an error naming the commercial model field', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(COMMERCIAL_MODEL_UPDATE_ERROR)) },
  ])('should return inactive without retrying when the hub rejects the refresh with $reason', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockRejection();

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect({ result, calls: mockPost.mock.calls.length }).toEqual({ result: { status: 'inactive', commercialModel: null, organizationName: null }, calls: 1 });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(INPUT_ERROR)) },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(INPUT_ERROR)) },
  ])('should return inactive without retrying when the hub rejects the refresh with $rejection', async ({ mockRejection }) => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockRejection();

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect({ result, calls: mockPost.mock.calls.length }).toEqual({ result: { status: 'inactive', commercialModel: null, organizationName: null }, calls: 1 });
  });

  it.each([
    { rejection: 'an HTTP 400 validation error', mockRejection: () => mockPost.mockRejectedValueOnce(badRequestError(INPUT_ERROR)), codes: ['BAD_USER_INPUT'] },
    { rejection: 'GraphQL errors in an HTTP 200 answer', mockRejection: () => mockPost.mockResolvedValueOnce(graphqlErrorResponse(INPUT_ERROR)), codes: [] },
  ])('should log the error codes but not the echoed token when the hub rejects the refresh with $rejection', async ({ mockRejection, codes }) => {
    // Given
    const { xtmHubClient, logApp } = await loadClient();
    mockRejection();

    // When
    await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect(vi.mocked(logApp.warn).mock.calls).toEqual([['XTM Hub sent an error', { codes, refusal: null }]]);
  });

  it('should return inactive when the hub is unreachable', async () => {
    // Given
    const { xtmHubClient } = await loadClient();
    mockPost.mockRejectedValueOnce(new HttpClientError('connect ECONNREFUSED', 'ECONNREFUSED'));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus(REFRESH_INPUT);

    // Then
    expect({ result, calls: mockPost.mock.calls.length }).toEqual({ result: { status: 'inactive', commercialModel: null, organizationName: null }, calls: 1 });
  });
});
