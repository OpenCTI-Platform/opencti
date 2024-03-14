/// <reference types="node" />
// TypeScript Version: 3.6

import * as http from 'http';
import * as https from 'https';
import * as http2 from 'http2';

import { URL } from 'url';
import * as jose from 'jose';
import * as crypto from 'crypto';
import { format } from 'util';

export type HttpOptions = Partial<
  Pick<
    https.RequestOptions,
    | 'agent'
    | 'ca'
    | 'cert'
    | 'crl'
    | 'headers'
    | 'key'
    | 'lookup'
    | 'passphrase'
    | 'pfx'
    | 'timeout'
  >
>;
export type RetryFunction = (retry: number, error: Error) => number;
export type CustomHttpOptionsProvider = (
  url: URL,
  options: Omit<https.RequestOptions, keyof URL>,
) => HttpOptions;
export type TokenTypeHint = 'access_token' | 'refresh_token' | string;
export type DPoPInput = crypto.KeyObject | Parameters<typeof crypto.createPrivateKey>[0];

interface UnknownObject {
  [key: string]: unknown;
}

export const custom: {
  setHttpOptionsDefaults(params: HttpOptions): undefined;
  readonly http_options: unique symbol;
  readonly clock_tolerance: unique symbol;
};

export type ResponseType = 'code' | 'id_token' | 'code id_token' | 'none' | string;
export type ClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'client_secret_jwt'
  | 'private_key_jwt'
  | 'tls_client_auth'
  | 'self_signed_tls_client_auth'
  | 'none';

export interface ClientMetadata {
  // important
  client_id: string;
  id_token_signed_response_alg?: string;
  token_endpoint_auth_method?: ClientAuthMethod;
  client_secret?: string;
  redirect_uris?: string[];
  response_types?: ResponseType[];
  post_logout_redirect_uris?: string[];
  default_max_age?: number;
  require_auth_time?: boolean;
  tls_client_certificate_bound_access_tokens?: boolean;
  request_object_signing_alg?: string;

  // less important
  id_token_encrypted_response_alg?: string;
  id_token_encrypted_response_enc?: string;
  introspection_endpoint_auth_method?: ClientAuthMethod;
  introspection_endpoint_auth_signing_alg?: string;
  request_object_encryption_alg?: string;
  request_object_encryption_enc?: string;
  revocation_endpoint_auth_method?: ClientAuthMethod;
  revocation_endpoint_auth_signing_alg?: string;
  token_endpoint_auth_signing_alg?: string;
  userinfo_encrypted_response_alg?: string;
  userinfo_encrypted_response_enc?: string;
  userinfo_signed_response_alg?: string;
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;
  authorization_signed_response_alg?: string;

  [key: string]: unknown;
}

export interface ClaimsParameterMember {
  essential?: boolean;
  value?: string;
  values?: string[];

  [key: string]: unknown;
}

export interface AuthorizationParameters {
  acr_values?: string;
  audience?: string;
  claims?:
    | string
    | {
        id_token?: {
          [key: string]: null | ClaimsParameterMember;
        };
        userinfo?: {
          [key: string]: null | ClaimsParameterMember;
        };
      };
  claims_locales?: string;
  client_id?: string;
  code_challenge_method?: string;
  code_challenge?: string;
  display?: string;
  id_token_hint?: string;
  login_hint?: string;
  max_age?: number;
  nonce?: string;
  prompt?: string;
  redirect_uri?: string;
  registration?: string;
  request_uri?: string;
  request?: string;
  resource?: string | string[];
  response_mode?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  ui_locales?: string;

  [key: string]: unknown;
}

export interface EndSessionParameters {
  id_token_hint?: TokenSet | string;
  post_logout_redirect_uri?: string;
  state?: string;
  client_id?: string;
  logout_hint?: string;

  [key: string]: unknown;
}

export interface CallbackParamsType {
  access_token?: string;
  code?: string;
  error?: string;
  error_description?: string;
  error_uri?: string;
  expires_in?: string;
  id_token?: string;
  state?: string;
  token_type?: string;
  session_state?: string;
  response?: string;

  [key: string]: unknown;
}

export interface OAuthCallbackChecks {
  response_type?: string;
  state?: string;
  code_verifier?: string;
  jarm?: boolean;
  scope?: string; // TODO: remove in v6.x
}

export interface OpenIDCallbackChecks extends OAuthCallbackChecks {
  max_age?: number;
  nonce?: string;
}

export interface CallbackExtras {
  exchangeBody?: object;
  clientAssertionPayload?: object;
  DPoP?: DPoPInput;
}

export interface RefreshExtras {
  exchangeBody?: object;
  clientAssertionPayload?: object;
  DPoP?: DPoPInput;
}

export interface GrantBody {
  grant_type: string;

  [key: string]: unknown;
}

export interface GrantExtras {
  clientAssertionPayload?: object;
  DPoP?: DPoPInput;
}

export interface IntrospectExtras {
  introspectBody?: object;
  clientAssertionPayload?: object;
}

export interface RevokeExtras {
  revokeBody?: object;
  clientAssertionPayload?: object;
}

export interface RequestObjectPayload extends AuthorizationParameters {
  client_id?: string;
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
  jti?: string;

  [key: string]: unknown;
}

export interface RegisterOther {
  jwks?: { keys: jose.JWK[] };
  initialAccessToken?: string;
}

export interface DeviceAuthorizationParameters {
  client_id?: string;
  scope?: string;

  [key: string]: unknown;
}

export interface DeviceAuthorizationExtras {
  exchangeBody?: object;
  clientAssertionPayload?: object;
  DPoP?: DPoPInput;
}

export interface PushedAuthorizationRequestExtras {
  clientAssertionPayload?: object;
}

export type Address<ExtendedAddress extends {} = UnknownObject> = Override<
  {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  },
  ExtendedAddress
>;

export type UserinfoResponse<
  UserInfo extends {} = UnknownObject,
  ExtendedAddress extends {} = UnknownObject,
> = Override<
  {
    sub: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    updated_at?: number;
    address?: Address<ExtendedAddress>;
  },
  UserInfo
>;

export interface IntrospectionResponse {
  active: boolean;
  client_id?: string;
  exp?: number;
  iat?: number;
  sid?: string;
  iss?: string;
  jti?: string;
  username?: string;
  aud?: string | string[];
  scope: string;
  sub?: string;
  nbf?: number;
  token_type?: string;
  cnf?: {
    'x5t#S256'?: string;

    [key: string]: unknown;
  };

  [key: string]: unknown;
}

export interface ClientOptions {
  additionalAuthorizedParties?: string | string[];
}

export type Client = InstanceType<Issuer['Client']>;
declare class BaseClient {
  constructor(metadata: ClientMetadata, jwks?: { keys: jose.JWK[] }, options?: ClientOptions);
  [custom.http_options]: CustomHttpOptionsProvider;
  [custom.clock_tolerance]: number;
  metadata: ClientMetadata;
  issuer: Issuer<this>;
  static issuer: Issuer<BaseClient>;

  authorizationUrl(parameters?: AuthorizationParameters): string;
  endSessionUrl(parameters?: EndSessionParameters): string;
  callbackParams(
    input: string | http.IncomingMessage | http2.Http2ServerRequest,
  ): CallbackParamsType;
  callback(
    redirectUri: string | undefined,
    parameters: CallbackParamsType,
    checks?: OpenIDCallbackChecks,
    extras?: CallbackExtras,
  ): Promise<TokenSet>;
  oauthCallback(
    redirectUri: string | undefined,
    parameters: CallbackParamsType,
    checks?: OAuthCallbackChecks,
    extras?: CallbackExtras,
  ): Promise<TokenSet>;
  refresh(refreshToken: TokenSet | string, extras?: RefreshExtras): Promise<TokenSet>;
  userinfo<TUserInfo extends {} = UnknownObject, TAddress extends {} = UnknownObject>(
    accessToken: TokenSet | string,
    options?: {
      method?: 'GET' | 'POST';
      via?: 'header' | 'body';
      tokenType?: string;
      params?: object;
      DPoP?: DPoPInput;
    },
  ): Promise<UserinfoResponse<TUserInfo, TAddress>>;
  requestResource(
    resourceUrl: string | URL,
    accessToken: TokenSet | string,
    options?: {
      headers?: object;
      body?: string | Buffer;
      method?: 'GET' | 'POST' | 'PUT' | 'HEAD' | 'DELETE' | 'OPTIONS' | 'TRACE' | 'PATCH';
      tokenType?: string;
      DPoP?: DPoPInput;
    },
  ): Promise<{ body?: Buffer } & http.IncomingMessage>;
  grant(body: GrantBody, extras?: GrantExtras): Promise<TokenSet>;
  introspect(
    token: string,
    tokenTypeHint?: TokenTypeHint,
    extras?: IntrospectExtras,
  ): Promise<IntrospectionResponse>;
  revoke(token: string, tokenTypeHint?: TokenTypeHint, extras?: RevokeExtras): Promise<undefined>;
  requestObject(payload: RequestObjectPayload): Promise<string>;
  deviceAuthorization(
    parameters?: DeviceAuthorizationParameters,
    extras?: DeviceAuthorizationExtras,
  ): Promise<DeviceFlowHandle<BaseClient>>;
  pushedAuthorizationRequest(
    parameters?: AuthorizationParameters,
    extras?: PushedAuthorizationRequestExtras,
  ): Promise<{
    request_uri: string;
    expires_in: number;
    [key: string]: unknown;
  }>;
  static register(metadata: object, other?: RegisterOther & ClientOptions): Promise<BaseClient>;
  static fromUri(
    registrationClientUri: string,
    registrationAccessToken: string,
    jwks?: { keys: jose.JWK[] },
    clientOptions?: ClientOptions,
  ): Promise<BaseClient>;
  static [custom.http_options]: CustomHttpOptionsProvider;

  [key: string]: unknown;
}

interface DeviceFlowPollOptions {
  // @ts-ignore
  signal?: AbortSignal;
}

export class DeviceFlowHandle<TClient extends BaseClient = BaseClient> {
  poll(options?: DeviceFlowPollOptions): Promise<TokenSet>;
  abort(): void;
  expired(): boolean;
  expires_at: number;
  client: TClient;
  user_code: string;
  device_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
}

export interface IssuerMetadata {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
  registration_endpoint?: string;
  token_endpoint_auth_methods_supported?: string[];
  token_endpoint_auth_signing_alg_values_supported?: string[];
  introspection_endpoint_auth_methods_supported?: string[];
  introspection_endpoint_auth_signing_alg_values_supported?: string[];
  revocation_endpoint_auth_methods_supported?: string[];
  revocation_endpoint_auth_signing_alg_values_supported?: string[];
  request_object_signing_alg_values_supported?: string[];
  mtls_endpoint_aliases?: MtlsEndpointAliases;

  [key: string]: unknown;
}

export interface MtlsEndpointAliases {
  token_endpoint?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  device_authorization_endpoint?: string;
}

export interface TypeOfGenericClient<TClient extends BaseClient = BaseClient> {
  new (metadata: ClientMetadata, jwks?: { keys: jose.JWK[] }, options?: ClientOptions): TClient;
  [custom.http_options]: CustomHttpOptionsProvider;
  [custom.clock_tolerance]: number;
}

export class Issuer<TClient extends BaseClient = BaseClient> {
  constructor(metadata: IssuerMetadata);

  Client: TypeOfGenericClient<TClient>;

  FAPI1Client: TypeOfGenericClient<TClient>;

  metadata: IssuerMetadata;
  [custom.http_options]: CustomHttpOptionsProvider;
  static discover(issuer: string): Promise<Issuer<BaseClient>>;
  static webfinger(input: string): Promise<Issuer<BaseClient>>;
  static [custom.http_options]: CustomHttpOptionsProvider;
  [key: string]: unknown;
}

export interface TokenSetParameters {
  access_token?: string;
  token_type?: string;
  id_token?: string;
  refresh_token?: string;
  scope?: string;

  expires_at?: number;
  session_state?: string;

  [key: string]: unknown;
}

export interface IdTokenClaims extends UserinfoResponse {
  acr?: string;
  amr?: string[];
  at_hash?: string;
  aud: string | string[];
  auth_time?: number;
  azp?: string;
  c_hash?: string;
  exp: number;
  iat: number;
  iss: string;
  nonce?: string;
  s_hash?: string;
  sub: string;

  [key: string]: unknown;
}

export class TokenSet implements TokenSetParameters {
  access_token?: string;
  token_type?: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  expires_at?: number;
  session_state?: string;
  scope?: string;

  constructor(input?: TokenSetParameters);

  expired(): boolean;
  claims(): IdTokenClaims;

  [key: string]: unknown;
}

export type StrategyVerifyCallbackUserInfo<
  TUser,
  TUserInfo extends {} = UnknownObject,
  TAddress extends {} = UnknownObject,
> = (
  tokenset: TokenSet,
  userinfo: UserinfoResponse<TUserInfo, TAddress>,
  done: (err: any, user?: TUser) => void,
) => void;
export type StrategyVerifyCallback<TUser> = (
  tokenset: TokenSet,
  done: (err: any, user?: TUser) => void,
) => void;
export type StrategyVerifyCallbackReqUserInfo<
  TUser,
  TUserInfo extends {} = UnknownObject,
  TAddress extends {} = UnknownObject,
> = (
  req: http.IncomingMessage,
  tokenset: TokenSet,
  userinfo: UserinfoResponse<TUserInfo, TAddress>,
  done: (err: any, user?: TUser) => void,
) => void;
export type StrategyVerifyCallbackReq<TUser> = (
  req: http.IncomingMessage,
  tokenset: TokenSet,
  done: (err: any, user?: TUser) => void,
) => void;

export interface StrategyOptions<TClient extends BaseClient = BaseClient> {
  client: TClient;
  params?: AuthorizationParameters;
  extras?: CallbackExtras;
  passReqToCallback?: boolean;
  usePKCE?: boolean | string;
  sessionKey?: string;
}

export class Strategy<TUser, TClient extends BaseClient = BaseClient> {
  constructor(
    options: StrategyOptions<TClient>,
    verify:
      | StrategyVerifyCallback<TUser>
      | StrategyVerifyCallbackUserInfo<TUser>
      | StrategyVerifyCallbackReq<TUser>
      | StrategyVerifyCallbackReqUserInfo<TUser>,
  );

  authenticate(req: any, options?: any): void;
  success(user: any, info?: any): void;
  fail(challenge: any, status: number): void;
  fail(status: number): void;
  redirect(url: string, status?: number): void;
  pass(): void;
  error(err: Error): void;
}

export namespace generators {
  function random(bytes?: number): string;
  function state(bytes?: number): string;
  function nonce(bytes?: number): string;
  function codeVerifier(bytes?: number): string;
  function codeChallenge(verifier: string): string;
}

export namespace errors {
  class OPError extends Error {
    error_description?: string;
    error?: string;
    error_uri?: string;
    state?: string;
    scope?: string;
    session_state?: string;
    response?: { body?: UnknownObject | Buffer } & http.IncomingMessage;

    constructor(
      params: {
        error: string;
        error_description?: string;
        error_uri?: string;
        state?: string;
        scope?: string;
        session_state?: string;
      },
      response?: { body?: UnknownObject | Buffer } & http.IncomingMessage,
    );
  }

  class RPError extends Error {
    jwt?: string;
    checks?: object;
    params?: object;
    body?: object;
    response?: { body?: UnknownObject | Buffer } & http.IncomingMessage;
    now?: number;
    tolerance?: number;
    nbf?: number;
    exp?: number;
    iat?: number;
    auth_time?: number;

    constructor(...args: Parameters<typeof format>);
    constructor(options: {
      message?: string;
      printf?: Parameters<typeof format>;
      response?: { body?: UnknownObject | Buffer } & http.IncomingMessage;
      [key: string]: unknown;
    });
  }
}

type KnownKeys<T> = {
  [K in keyof T]: string extends K ? never : number extends K ? never : K;
} extends { [_ in keyof T]: infer U }
  ? {} extends U
    ? never
    : U
  : never;
type Override<T1, T2> = Omit<T1, keyof Omit<T2, keyof KnownKeys<T2>>> & T2;
