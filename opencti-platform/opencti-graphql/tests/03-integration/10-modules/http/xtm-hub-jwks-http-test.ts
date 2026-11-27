import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { importJWK, jwtVerify } from 'jose';
import { API_URI, testContext } from '../../../utils/testQuery';
import { queryAsAdmin } from '../../../utils/testQueryHelper';
import { getSettings } from '../../../../src/domain/settings';
import { basePath } from '../../../../src/config/conf';
import { getXtmHubKey, XTM_HUB_ASSERTION_AUDIENCE, XTM_HUB_ASSERTION_TYPE, type XtmHubPublicJwk } from '../../../../src/modules/xtm/hub/xtm-hub-key';

const XTM_HUB_JWKS_URL = `${API_URI}${basePath}/xtm/hub/jwks`;
const PLATFORM_ID = 'b4a5e3c2-7f0e-4c39-9d6e-2f1a8c3b5d71';

const SETTINGS_EDIT_MUTATION = gql`
  mutation XtmHubKeySettingsEdit($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const readJwks = async (res: Response) => (await res.json()) as { keys: XtmHubPublicJwk[] };
const fetchJwks = async () => readJwks(await fetch(XTM_HUB_JWKS_URL));

describe('XTM Hub JWKS HTTP integration', () => {
  it('should serve the public key without authentication', async () => {
    const res = await fetch(XTM_HUB_JWKS_URL);

    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');
    const jwks = await readJwks(res);
    expect(jwks.keys).toHaveLength(1);
    const [jwk] = jwks.keys;
    expect(Object.keys(jwk).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x']);
    expect(jwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig' });
  });

  it('should serve the key of the default version, the same on every call', async () => {
    const first = await fetchJwks();
    const second = await fetchJwks();
    const key = await getXtmHubKey();

    expect(key.version).toBe(1);
    expect(first).toEqual({ keys: [key.publicJwk] });
    expect(second).toEqual(first);
  });

  it('should verify an assertion of this platform with the served key alone', async () => {
    const { keys: [jwk] } = await fetchJwks();
    const key = await getXtmHubKey();

    const assertion = await key.signAssertion({ platformId: PLATFORM_ID });
    const { payload, protectedHeader } = await jwtVerify(assertion, await importJWK(jwk, 'EdDSA'), {
      algorithms: ['EdDSA'],
      audience: XTM_HUB_ASSERTION_AUDIENCE,
      issuer: PLATFORM_ID,
      typ: XTM_HUB_ASSERTION_TYPE,
    });

    expect(protectedHeader.kid).toBe(jwk.kid);
    expect(payload.jti).toBeDefined();
  });

  // Only the XTM Hub enrollment writes the key version: another one would sign with a key XTM Hub does not hold.
  it.each([
    ['xtm_hub_key_version', 2],
    ['xtm_hub_key_enrolled_at', '2026-01-01T00:00:00.000Z'],
  ])('should refuse settingsEdit on %s, even for a BYPASS user', async (key, value) => {
    const before = await fetchJwks();
    const { id } = await getSettings(testContext);

    const result = await queryAsAdmin({ query: SETTINGS_EDIT_MUTATION, variables: { id, input: { key, value: [value] } } });

    expect(result.errors?.[0].message).toContain('cannot be edited');
    expect(await fetchJwks()).toEqual(before);
  });
});
