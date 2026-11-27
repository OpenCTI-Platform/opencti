import crypto from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { createCryptoKeyFactory } from '../../../../../src/utils/platformCrypto';
import {
  deriveXtmHubKey,
  getXtmHubJwks,
  resolveXtmHubKeyVersion,
  XTM_HUB_ASSERTION_AUDIENCE,
  XTM_HUB_ASSERTION_LIFETIME_SECONDS,
  XTM_HUB_ASSERTION_TYPE,
} from '../../../../../src/modules/xtm/hub/xtm-hub-key';
import { getEntityFromCache } from '../../../../../src/database/cache';

const TEST_SEED = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes, as the platform encryption key
const PLATFORM_ID = 'b4a5e3c2-7f0e-4c39-9d6e-2f1a8c3b5d71';

vi.mock('../../../../../src/database/cache', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, getEntityFromCache: vi.fn() };
});
vi.mock('../../../../../src/utils/platformCrypto', async (importOriginal) => {
  const actual: any = await importOriginal();
  return { ...actual, getPlatformCrypto: vi.fn(async () => actual.createCryptoKeyFactory(Buffer.from('a'.repeat(64), 'hex'))) };
});

// What the key must be, computed without platformCrypto: HKDF-SHA256 of the
// encryption key (empty salt) under the label of the XTM Hub path, then the
// Ed25519 public key of that seed. If this ever changes, every enrolled
// instance loses the key XTM Hub holds for it.
const expectedPublicX = (seed: Buffer, version: number) => {
  const info = `xtm-hub:platform-assertion:ed25519:seed::v${version}`;
  const privateSeed = Buffer.from(crypto.hkdfSync('sha256', seed, Buffer.alloc(0), Buffer.from(info), 32));
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, privateSeed]), format: 'der', type: 'pkcs8' });
  const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  return jwk.x;
};

describe('XTM Hub key: derivation', () => {
  it('should derive the same key for the same version after a restart', async () => {
    // Two factories built from the same encryption key stand for two starts (or two nodes).
    const first = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);
    const second = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);

    expect(second.publicJwk).toEqual(first.publicJwk);
    expect(first.publicJwk.x).toBe(expectedPublicX(TEST_SEED, 1));
  });

  it('should derive another key and kid for the next version', async () => {
    const factory = createCryptoKeyFactory(Buffer.from(TEST_SEED));
    const versionOne = await deriveXtmHubKey(factory, 1);
    const versionTwo = await deriveXtmHubKey(factory, 2);

    expect(versionTwo.publicJwk.x).not.toBe(versionOne.publicJwk.x);
    expect(versionTwo.publicJwk.kid).not.toBe(versionOne.publicJwk.kid);
    expect(versionTwo.publicJwk.x).toBe(expectedPublicX(TEST_SEED, 2));
  });

  it('should derive a key of its own, not the XTM auth key', async () => {
    const factory = createCryptoKeyFactory(Buffer.from(TEST_SEED));
    const hubKey = await deriveXtmHubKey(factory, 1);
    const authKey = await factory.deriveEd25519KeyPair(['authentication', 'xtm'], 1);

    expect(hubKey.publicJwk.x).not.toBe(authKey.jwks.keys[0].x);
    expect(hubKey.publicJwk.kid).not.toBe(authKey.jwks.keys[0].kid);
  });

  it('should expose only the public part of the key', async () => {
    const key = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);

    expect(Object.keys(key).sort()).toEqual(['publicJwk', 'signAssertion', 'version']);
    expect(Object.keys(key.publicJwk).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x']);
    expect(key.publicJwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', use: 'sig' });
    expect(Buffer.from(key.publicJwk.x, 'base64url')).toHaveLength(32);
  });

  it.each([0, -1, 1.5, Number.NaN])('should refuse version %s', async (version) => {
    await expect(deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), version)).rejects.toThrow(/Invalid XTM Hub key version/);
  });
});

describe('XTM Hub key: version', () => {
  it('should start at version 1 when no version is stored', () => {
    expect(resolveXtmHubKeyVersion({})).toBe(1);
    expect(resolveXtmHubKeyVersion({ xtm_hub_key_version: null as unknown as undefined })).toBe(1);
  });

  it('should use the stored version', () => {
    expect(resolveXtmHubKeyVersion({ xtm_hub_key_version: 3 })).toBe(3);
  });

  // Another key than the one XTM Hub holds would fail every call: refuse rather than fall back to version 1.
  it.each([0, -2, 2.5, '1'])('should refuse the malformed stored version %s', (version) => {
    expect(() => resolveXtmHubKeyVersion({ xtm_hub_key_version: version as number })).toThrow(/Invalid XTM Hub key version/);
  });
});

describe('XTM Hub key: assertion', () => {
  it('should sign an assertion that verifies with the public JWK', async () => {
    const key = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);

    const assertion = await key.signAssertion({ platformId: PLATFORM_ID });
    const { payload, protectedHeader } = await jwtVerify(assertion, await importJWK(key.publicJwk, 'EdDSA'), {
      algorithms: ['EdDSA'],
      audience: XTM_HUB_ASSERTION_AUDIENCE,
      issuer: PLATFORM_ID,
      typ: XTM_HUB_ASSERTION_TYPE,
    });

    expect(protectedHeader).toEqual({ alg: 'EdDSA', kid: key.publicJwk.kid, typ: 'xtm-hub-platform+jwt' });
    expect(payload.iss).toBe(PLATFORM_ID);
    expect(payload.aud).toBe('xtm-hub');
    expect(payload.identifier).toBe('opencti');
    expect(payload.exp! - payload.iat!).toBe(XTM_HUB_ASSERTION_LIFETIME_SECONDS);
    expect(XTM_HUB_ASSERTION_LIFETIME_SECONDS).toBe(60);
    expect(payload.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(payload).not.toHaveProperty('htu');
  });

  it('should carry the target path when one is given', async () => {
    const key = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);
    const htu = '/document/get/0f6c-service/1d2e-file';

    const assertion = await key.signAssertion({ platformId: PLATFORM_ID, htu });
    const { payload } = await jwtVerify(assertion, await importJWK(key.publicJwk, 'EdDSA'), { algorithms: ['EdDSA'] });

    expect(payload.htu).toBe(htu);
  });

  it('should give every assertion its own jti', async () => {
    const key = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);
    const publicKey = await importJWK(key.publicJwk, 'EdDSA');

    const first = await jwtVerify(await key.signAssertion({ platformId: PLATFORM_ID }), publicKey);
    const second = await jwtVerify(await key.signAssertion({ platformId: PLATFORM_ID }), publicKey);

    expect(second.payload.jti).not.toBe(first.payload.jti);
  });

  it('should not verify with the key of another version', async () => {
    const factory = createCryptoKeyFactory(Buffer.from(TEST_SEED));
    const versionOne = await deriveXtmHubKey(factory, 1);
    const versionTwo = await deriveXtmHubKey(factory, 2);

    const assertion = await versionOne.signAssertion({ platformId: PLATFORM_ID });

    expect(decodeProtectedHeader(assertion).kid).toBe(versionOne.publicJwk.kid);
    await expect(jwtVerify(assertion, await importJWK(versionTwo.publicJwk, 'EdDSA'))).rejects.toThrow();
  });

  it('should refuse to sign without a platform id', async () => {
    const key = await deriveXtmHubKey(createCryptoKeyFactory(Buffer.from(TEST_SEED)), 1);

    await expect(key.signAssertion({ platformId: '' })).rejects.toThrow(/platform id/);
  });

  // TODO: verify against the sample assertion XTM Hub will publish for its verifier.
  it.todo('should match the XTM Hub reference sample');
});

describe('XTM Hub key: JWK Set', () => {
  beforeEach(() => {
    vi.mocked(getEntityFromCache).mockReset();
  });

  it('should serve the public key of the stored version', async () => {
    const factory = createCryptoKeyFactory(Buffer.from(TEST_SEED));
    vi.mocked(getEntityFromCache).mockResolvedValue({ xtm_hub_key_version: 2 } as any);

    const jwks = await getXtmHubJwks();

    expect(jwks).toEqual({ keys: [(await deriveXtmHubKey(factory, 2)).publicJwk] });
    expect(JSON.stringify(jwks)).not.toMatch(/"d"/);
  });

  it('should serve the version 1 key while no version is stored', async () => {
    const factory = createCryptoKeyFactory(Buffer.from(TEST_SEED));
    vi.mocked(getEntityFromCache).mockResolvedValue({} as any);

    const jwks = await getXtmHubJwks();

    expect(jwks.keys).toEqual([(await deriveXtmHubKey(factory, 1)).publicJwk]);
  });
});
