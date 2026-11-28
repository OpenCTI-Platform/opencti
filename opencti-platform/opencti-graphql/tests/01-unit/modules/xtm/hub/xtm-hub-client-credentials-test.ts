import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose';

const { mockPost, mockSignAssertion } = vi.hoisted(() => ({ mockPost: vi.fn(), mockSignAssertion: vi.fn() }));

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

// The key itself is covered by xtm-hub-key-test: here, only how the client uses it.
vi.mock('../../../../../src/modules/xtm/hub/xtm-hub-key', () => ({
  getXtmHubKey: vi.fn(async () => ({ version: 1, publicJwk: {}, signAssertion: mockSignAssertion })),
}));

const { xtmHubClient, XTM_HUB_ASSERTION_HEADER } = await import('../../../../../src/modules/xtm/hub/xtm-hub-client');
const { HttpClientError } = await import('../../../../../src/utils/http-client');

const PLATFORM_ID = 'b4a5e3c2-7f0e-4c39-9d6e-2f1a8c3b5d71';
const TOKEN = 'platform-token';
const TOKEN_CREDENTIALS = { kind: 'token' as const, token: TOKEN };
const KEY_CREDENTIALS = { kind: 'key' as const };
const TOKEN_HEADERS = { 'XTM-Hub-Platform-Token': TOKEN, 'XTM-Hub-Platform-Id': PLATFORM_ID };

// Signs as the platform key does: an EdDSA JWT with a jti of its own.
const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
const PUBLIC_JWK = { ...(await exportJWK(publicKey)), alg: 'EdDSA', use: 'sig', kid: 'test-kid' } as any;
const signTestAssertion = async ({ platformId }: { platformId: string }) => new SignJWT({ identifier: 'opencti' })
  .setProtectedHeader({ alg: 'EdDSA', kid: 'test-kid', typ: 'xtm-hub-platform+jwt' })
  .setIssuer(platformId)
  .setAudience('xtm-hub')
  .setIssuedAt()
  .setExpirationTime('60s')
  .setJti(crypto.randomUUID())
  .sign(privateKey);

const httpResponse = (data: unknown) => ({ status: 200, statusText: 'OK', headers: {}, data });
const graphqlErrors = (...errors: { message: string; code?: string }[]) => ({
  data: null,
  errors: errors.map(({ message, code }) => ({ message, ...(code ? { extensions: { code } } : {}) })),
});
const httpError = (status: number, data: unknown) => new HttpClientError(`Request failed with status code ${status}`, status >= 500 ? 'ERR_BAD_RESPONSE' : 'ERR_BAD_REQUEST', {
  status,
  statusText: '',
  headers: {},
  data,
});

const sentHeaders = () => mockPost.mock.calls.map(([, , options]) => options?.headers ?? {});
const sentInputs = () => mockPost.mock.calls.map(([, body]) => body.variables?.input);

// The four calls a registered platform makes, each with the credentials it is given.
const platformCalls = [
  {
    name: 'refreshRegistrationStatus',
    call: (credentials: any) => xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, credentials, platformVersion: '7.0.0', platformContract: 'CE' }),
    answer: { data: { refreshPlatformRegistrationConnectivityStatus: { status: 'active' } } },
  },
  {
    name: 'autoRegister',
    call: (credentials: any) => xtmHubClient.autoRegister({ platformId: PLATFORM_ID, credentials, platformUrl: 'http://opencti.test', platformTitle: 'OpenCTI' }, 'CE', 3),
    answer: { data: { autoRegisterPlatform: { success: true } } },
  },
  {
    name: 'consumeProvisionedNewsFeedItems',
    call: (credentials: any) => xtmHubClient.consumeProvisionedNewsFeedItems(PLATFORM_ID, credentials),
    answer: { data: { consumeProvisionedNewsFeedItems: { news_feed_items: [], available_news_feed_types: [] } } },
  },
  {
    name: 'contactUs',
    call: (credentials: any) => xtmHubClient.contactUs({ platformId: PLATFORM_ID, credentials }, 'Hello'),
    answer: { data: { contactUs: { success: true } } },
  },
];

describe('xtmHubClient: platform credentials', () => {
  beforeEach(() => {
    mockPost.mockReset();
    mockSignAssertion.mockReset();
    mockSignAssertion.mockImplementation(signTestAssertion);
  });

  it.each(platformCalls)('$name should send the token headers and no assertion before enrollment', async ({ call, answer }) => {
    // Given
    mockPost.mockResolvedValue(httpResponse(answer));

    // When
    await call(TOKEN_CREDENTIALS);

    // Then
    const [headers] = sentHeaders();
    expect(headers).not.toHaveProperty(XTM_HUB_ASSERTION_HEADER);
    expect(mockSignAssertion).not.toHaveBeenCalled();
  });

  it.each(platformCalls.filter(({ name }) => name !== 'refreshRegistrationStatus'))('$name should send the token in the headers before enrollment', async ({ call, answer }) => {
    // Given
    mockPost.mockResolvedValue(httpResponse(answer));

    // When
    await call(TOKEN_CREDENTIALS);

    // Then
    expect(sentHeaders()).toEqual([TOKEN_HEADERS]);
  });

  it('refreshRegistrationStatus should keep the token in its input before enrollment, as before', async () => {
    // Given
    mockPost.mockResolvedValue(httpResponse(platformCalls[0].answer));

    // When
    await platformCalls[0].call(TOKEN_CREDENTIALS);

    // Then
    expect({ headers: sentHeaders(), input: sentInputs()[0] }).toEqual({
      headers: [{}],
      input: { platformId: PLATFORM_ID, token: TOKEN, platformVersion: '7.0.0', platformIdentifier: 'opencti', platformContract: 'CE' },
    });
  });

  it.each(platformCalls)('$name should send only a signed assertion once enrolled, never the token', async ({ call, answer }) => {
    // Given
    mockPost.mockResolvedValue(httpResponse(answer));

    // When
    await call(KEY_CREDENTIALS);

    // Then
    const [headers] = sentHeaders();
    expect(Object.keys(headers)).toEqual([XTM_HUB_ASSERTION_HEADER]);
    expect(JSON.stringify(mockPost.mock.calls)).not.toContain(TOKEN);
    // No htu: these calls open no single resource.
    expect(mockSignAssertion.mock.calls).toEqual([[{ platformId: PLATFORM_ID }]]);
    expect(decodeJwt(headers[XTM_HUB_ASSERTION_HEADER])).toMatchObject({ iss: PLATFORM_ID, aud: 'xtm-hub' });
  });

  it('refreshRegistrationStatus should leave the token out of its input once enrolled', async () => {
    // Given
    mockPost.mockResolvedValue(httpResponse(platformCalls[0].answer));

    // When
    await platformCalls[0].call(KEY_CREDENTIALS);

    // Then
    expect(sentInputs()).toEqual([{ platformId: PLATFORM_ID, platformVersion: '7.0.0', platformIdentifier: 'opencti', platformContract: 'CE' }]);
  });

  it.each(platformCalls)('$name should sign a new assertion, with a new jti, for every call', async ({ call, answer }) => {
    // Given
    mockPost.mockResolvedValue(httpResponse(answer));

    // When
    await call(KEY_CREDENTIALS);
    await call(KEY_CREDENTIALS);

    // Then
    const assertions = sentHeaders().map((headers) => headers[XTM_HUB_ASSERTION_HEADER]);
    const jtis = assertions.map((assertion) => decodeJwt(assertion).jti);
    expect(assertions).toHaveLength(2);
    expect(new Set(jtis).size).toBe(2);
  });

  it('refreshRegistrationStatus should sign a new assertion when it retries without a field an older XTM Hub rejects', async () => {
    // Given
    mockPost
      .mockResolvedValueOnce(httpResponse(graphqlErrors({ message: 'Cannot query field "commercialModel" on type "X".' })))
      .mockResolvedValueOnce(httpResponse(platformCalls[0].answer));

    // When
    const result = await xtmHubClient.refreshRegistrationStatus({ platformId: PLATFORM_ID, credentials: KEY_CREDENTIALS, platformVersion: '7.0.0', platformContract: 'CE' });

    // Then
    const jtis = sentHeaders().map((headers) => decodeJwt(headers[XTM_HUB_ASSERTION_HEADER]).jti);
    expect({ status: result.status, calls: jtis.length, distinct: new Set(jtis).size }).toEqual({ status: 'active', calls: 2, distinct: 2 });
  });
});

describe('xtmHubClient.enrollPlatformKey', () => {
  const ASSERTION = 'signed-assertion';
  const enroll = () => xtmHubClient.enrollPlatformKey({ platformId: PLATFORM_ID, token: TOKEN }, PUBLIC_JWK, ASSERTION);

  beforeEach(() => {
    mockPost.mockReset();
  });

  it('should send the token headers, the assertion and the public key', async () => {
    // Given
    mockPost.mockResolvedValueOnce(httpResponse({ data: { enrollPlatformKey: { status: 'enrolled' } } }));

    // When
    await enroll();

    // Then
    const [[url, body, options]] = mockPost.mock.calls;
    expect({ url, query: body.query.replace(/\s+/g, ' ').trim(), variables: body.variables, headers: options.headers }).toEqual({
      url: '/graphql-api',
      query: 'mutation EnrollPlatformKey($input: EnrollPlatformKeyInput!) { enrollPlatformKey(input: $input) { status } }',
      variables: { input: { publicKey: PUBLIC_JWK } },
      headers: { ...TOKEN_HEADERS, [XTM_HUB_ASSERTION_HEADER]: ASSERTION },
    });
  });

  it.each([
    { status: 'enrolled', outcome: 'enrolled' },
    { status: 'conflict', outcome: 'conflict' },
    { status: 'not_found', outcome: 'not_found' },
    { status: 'key_mismatch', outcome: 'key_mismatch' },
    { status: 'not_available', outcome: 'not_available' },
    { status: 'ENROLLED', outcome: 'enrolled' },
    { status: 'NOT_AVAILABLE', outcome: 'not_available' },
    { status: 'something_new', outcome: 'refused' },
    { status: null, outcome: 'refused' },
  ])('should read the answer $status as $outcome', async ({ status, outcome }) => {
    // Given
    mockPost.mockResolvedValueOnce(httpResponse({ data: { enrollPlatformKey: { status } } }));

    // When
    const result = await enroll();

    // Then
    expect(result).toBe(outcome);
  });

  it.each([
    {
      answer: 'a validation error from an older XTM Hub (HTTP 400)',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(400, graphqlErrors({
        message: 'Cannot query field "enrollPlatformKey" on type "Mutation".',
        code: 'GRAPHQL_VALIDATION_FAILED',
      }))),
      outcome: 'unknown_operation',
    },
    {
      answer: 'a validation error from an older XTM Hub (HTTP 200)',
      mockAnswer: () => mockPost.mockResolvedValueOnce(httpResponse(graphqlErrors({ message: 'Unknown type "EnrollPlatformKeyInput".', code: 'GRAPHQL_VALIDATION_FAILED' }))),
      outcome: 'unknown_operation',
    },
    {
      answer: 'an unknown operation without an error code',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(400, graphqlErrors({ message: 'Cannot query field "enrollPlatformKey" on type "Mutation".' }))),
      outcome: 'unknown_operation',
    },
    {
      answer: 'PLATFORM_KEY_MISMATCH',
      mockAnswer: () => mockPost.mockResolvedValueOnce(httpResponse(graphqlErrors({ message: 'Refused', code: 'PLATFORM_KEY_MISMATCH' }))),
      outcome: 'key_mismatch',
    },
    {
      answer: 'PLATFORM_TOKEN_REFUSED',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(401, graphqlErrors({ message: 'Refused', code: 'PLATFORM_TOKEN_REFUSED' }))),
      outcome: 'not_found',
    },
    {
      answer: 'PLATFORM_TOKEN_PATH_CLOSED',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(401, graphqlErrors({ message: 'Refused', code: 'PLATFORM_TOKEN_PATH_CLOSED' }))),
      outcome: 'not_found',
    },
    {
      answer: 'PLATFORM_ASSERTION_INVALID',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(401, graphqlErrors({ message: 'Refused', code: 'PLATFORM_ASSERTION_INVALID' }))),
      outcome: 'refused',
    },
    {
      answer: 'another GraphQL error',
      mockAnswer: () => mockPost.mockResolvedValueOnce(httpResponse(graphqlErrors({ message: 'Forbidden', code: 'FORBIDDEN_ACCESS' }))),
      outcome: 'refused',
    },
    {
      answer: 'an HTTP 403 without a GraphQL body',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(403, 'Forbidden')),
      outcome: 'refused',
    },
    {
      answer: 'a network failure',
      mockAnswer: () => mockPost.mockRejectedValueOnce(new HttpClientError('connect ECONNREFUSED', 'ECONNREFUSED')),
      outcome: 'unreachable',
    },
    {
      answer: 'a timeout',
      mockAnswer: () => mockPost.mockRejectedValueOnce(new Error('The operation was aborted due to timeout')),
      outcome: 'unreachable',
    },
    {
      answer: 'an HTTP 503',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(503, 'Service Unavailable')),
      outcome: 'unreachable',
    },
    {
      answer: 'an HTTP 500 with GraphQL errors',
      mockAnswer: () => mockPost.mockRejectedValueOnce(httpError(500, graphqlErrors({ message: 'Boom', code: 'INTERNAL_SERVER_ERROR' }))),
      outcome: 'unreachable',
    },
  ])('should read $answer as $outcome', async ({ mockAnswer, outcome }) => {
    // Given
    mockAnswer();

    // When
    const result = await enroll();

    // Then
    expect(result).toBe(outcome);
  });

  it('should not log the token, the assertion nor the error messages', async () => {
    // Given
    const { logApp } = await import('../../../../../src/config/conf');
    vi.mocked(logApp.warn).mockClear();
    mockPost.mockRejectedValueOnce(httpError(400, graphqlErrors({ message: `Variable "$input" got invalid value ${TOKEN}`, code: 'BAD_USER_INPUT' })));

    // When
    await enroll();

    // Then
    const logged = JSON.stringify(vi.mocked(logApp.warn).mock.calls);
    expect(logged).not.toContain(TOKEN);
    expect(logged).not.toContain(ASSERTION);
  });
});
