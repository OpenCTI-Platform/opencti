import { IncomingMessage } from 'http';
import { generateKeyPairSync } from 'crypto';

import {
  custom,
  generators,
  Issuer,
  Client,
  Strategy,
  StrategyVerifyCallback,
  StrategyOptions,
  TokenSet,
  RegisterOther,
  IssuerMetadata,
} from './index.d';
import passport from 'passport';

async (req: IncomingMessage) => {
  // Custom HTTP options on the `Issuer` _c'tor_ (e.g. used for `Issuer.discover()`):
  Issuer[custom.http_options] = () => ({ timeout: 10000 });

  let issuer = await Issuer.discover('https://accounts.google.com');
  console.log('Discovered issuer %O', issuer.metadata.issuer);

  //
  issuer = new Issuer({
    issuer: 'https://accounts.google.com',
    authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_endpoint: 'https://oauth2.googleapis.com/token',
    userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    revocation_endpoint: 'https://oauth2.googleapis.com/revoke',
    jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  });

  issuer[custom.http_options] = () => ({ timeout: 10000 });

  //

  issuer.Client[custom.http_options] = () => ({ timeout: 10000 });

  const client = new issuer.Client({
    client_id: 'c',
    client_secret: 's',
    redirect_uris: ['http://localhost:3000/cb'],
    response_types: ['code'],
  });
  console.log(client.metadata.client_id);

  // Custom HTTP options on the `Client` _instance_
  client[custom.http_options] = () => ({ timeout: 10000 });
  client[custom.clock_tolerance] = 5;

  //

  const { privateKey: keyobject } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { kty: 'EC', x: 'foo', y: 'bar', d: 'baz', crv: 'P-256' };

  client.callback('https://rp.example.com/cb', {}, {}, { DPoP: keyobject });
  client.callback('https://rp.example.com/cb', {}, {}, { DPoP: { key: jwk, format: 'jwk' } });

  client.oauthCallback('https://rp.example.com/cb', {}, {}, { DPoP: keyobject });
  client.oauthCallback('https://rp.example.com/cb', {}, {}, { DPoP: { key: jwk, format: 'jwk' } });

  client.userinfo('token', { DPoP: keyobject });
  client.userinfo('token', { DPoP: { key: jwk, format: 'jwk' } });

  client.requestResource('https://rs.example.com/resource', 'token', { DPoP: keyobject });
  client.requestResource('https://rs.example.com/resource', 'token', {
    DPoP: { key: jwk, format: 'jwk' },
  });

  client.pushedAuthorizationRequest();
  client.pushedAuthorizationRequest({});
  client.pushedAuthorizationRequest({ foo: 'bar' });
  client.pushedAuthorizationRequest({ foo: 'bar' }, { clientAssertionPayload: {} });

  {
    const { request_uri, expires_in } = await client.pushedAuthorizationRequest();
    request_uri.substring(0);
    expires_in.toFixed();
  }

  client.deviceAuthorization({}, { DPoP: keyobject });
  const handle = await client.deviceAuthorization({}, { DPoP: { key: jwk, format: 'jwk' } });

  handle.abort();
  handle.poll();

  const ac = new AbortController();
  handle.poll({ signal: ac.signal });

  client.grant({ grant_type: 'client_credentials' }, { DPoP: keyobject });
  client.grant({ grant_type: 'client_credentials' }, { DPoP: { key: jwk, format: 'jwk' } });

  client.refresh('token', { DPoP: keyobject });
  client.refresh('token', { DPoP: { key: jwk, format: 'jwk' } });

  //

  const code_verifier = generators.codeVerifier();

  const code_challenge = generators.codeChallenge(code_verifier);

  //

  client
    .authorizationUrl({
      scope: 'openid email profile',
      response_mode: 'form_post',
      nonce: 'nonce',
      resource: 'https://my.api.example.com/resource/32178',
      code_challenge,
      code_challenge_method: 'S256',
    })
    .substring(0);

  //

  const params = client.callbackParams(req);
  const callbackResponse = await client.callback('https://client.example.com/callback', params, {
    code_verifier,
  });
  console.log(
    callbackResponse.id_token,
    callbackResponse.access_token,
    callbackResponse.refresh_token,
  );
  console.log(
    callbackResponse.expired(),
    callbackResponse.claims()['some claim name'],
    callbackResponse.claims().sub,
  );

  //

  await client.userinfo('access token');
  const userinfo = await client.userinfo(callbackResponse);
  console.log(userinfo['some user info name']);

  //

  const userinfoGeneric = await client.userinfo<{ someProp: number }>(callbackResponse);
  console.log(userinfoGeneric.someProp);

  //

  const userinfoAddressGeneric = await client.userinfo<{ someProp: number }, { street: string }>(
    callbackResponse,
  );
  console.log(
    userinfoAddressGeneric.address ? userinfoAddressGeneric.address.street.substring(0) : undefined,
  );

  //

  const userinfoOverride = await client.userinfo<{ email_verified: string }>(callbackResponse);
  console.log(userinfoOverride.email_verified.substring(0));

  //

  await client.requestResource('https://rs.example.com/resource', 'access token', {
    headers: { Accept: 'application/json' },
  });
  const resource = await client.requestResource(
    'https://rs.example.com/resource',
    callbackResponse,
    { headers: { Accept: 'application/json' } },
  );
  console.log(resource.body!.byteLength);
  console.log(resource.body!.toString('utf-8'));

  //

  const grantResponse = await client.grant({
    grant_type: 'client_credentials',
    acr_values: 'acr_values',
  });
  console.log(grantResponse.access_token);

  //

  const introspectResponse = await client.introspect('token');
  const active: boolean = introspectResponse.active;
  console.log(introspectResponse['some claim name']);

  client.introspect('token', 'tokenTypeHint');

  client.introspect('token', 'tokenTypeHint', {});
  client.introspect('token', 'tokenTypeHint', { introspectBody: {} });

  //

  client.endSessionUrl({ id_token_hint: 'id_token_hint' }).substring(0);

  //

  await client.revoke('token', 'hint');
  client.revoke('token', 'hint', {});
  client.revoke('token', 'hint', { revokeBody: {}, clientAssertionPayload: {} });

  await client.refresh('token');
  await client.refresh('token', {});
  await client.refresh('token', { exchangeBody: {}, clientAssertionPayload: {} });

  // generics setup
  class CustomClient extends issuer.Client {
    myCustomMethod() {}

    static async register(metadata: object, other?: RegisterOther): Promise<CustomClient> {
      return new CustomClient({
        client_id: 'xxxx',
      });
    }
  }

  // generics: issuer

  class CustomIssuer extends Issuer<CustomClient> {
    constructor(metadata: IssuerMetadata) {
      super(metadata);
    }
  }

  const customIssuer = new CustomIssuer({
    issuer: 'test-issuer',
  });

  const customIssuedClient = new customIssuer.Client({
    client_id: 'c',
    client_secret: 's',
    redirect_uris: ['http://localhost:3000/cb'],
    response_types: ['code'],
  });

  customIssuedClient.myCustomMethod();

  // generics: strategy
  class PassportUser {
    tokenset: TokenSet;

    constructor(tokenset: TokenSet) {
      this.tokenset = tokenset;
    }

    getAccessToken() {
      return this.tokenset.access_token;
    }
  }

  const verify: StrategyVerifyCallback<PassportUser> = (tokenset, done) => {
    const user = new PassportUser(tokenset);
    const accessToken = user.getAccessToken();
    done(null, user);
  };

  class CustomStrategy extends Strategy<PassportUser, CustomClient> {
    client: CustomClient;

    constructor(
      options: StrategyOptions<CustomClient>,
      verify: StrategyVerifyCallback<PassportUser>,
    ) {
      super(options, verify);

      this.client = options.client;
    }
  }

  const customClient = await CustomClient.register({});

  const strategyOptions = {
    client: customClient,
  };

  strategyOptions.client.myCustomMethod();

  const customStrategy = new CustomStrategy(strategyOptions, verify);

  passport.use('oidc', new Strategy({ client, params: { foo: 'bar ' } }, verify));
};
