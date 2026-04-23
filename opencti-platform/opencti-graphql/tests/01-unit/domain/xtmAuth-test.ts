import { describe, expect, it, vi, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

// --- Mocks (hoisted before module evaluation) ---

vi.mock('../../../src/config/conf', () => ({
  default: {
    get: (key: string) => {
      const config: Record<string, any> = {
        'xtm:xtm_one_url': 'https://xtm-one.example.com',
        'xtm:auth:token_ttl': 300,
      };
      return config[key];
    },
  },
  getBaseUrl: () => 'https://opencti.example.com',
  logApp: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
  DEV_MODE: false,
  ENABLED_DEMO_MODE: false,
  logAudit: { info: vi.fn() },
  booleanConf: (_key: string, defaultValue: boolean): boolean => defaultValue,
}));

vi.mock('../../../src/utils/platformCrypto', () => ({
  getPlatformCrypto: vi.fn(),
}));

// --- Imports (resolved after mocks are set up) ---

import { getPlatformCrypto } from '../../../src/utils/platformCrypto';
import { getXtmJwks, isOwnIssuer, isTrustedIssuer, issueXtmJwt, verifyXtmJwt } from '../../../src/domain/xtm-auth';

// --- Constants ---

const PLATFORM_URL = 'https://opencti.example.com';
const TRUSTED_XTM_URL = 'https://xtm-one.example.com';
const KID = 'test-kid-1';

// --- Test key pair setup ---

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA');
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = 'EdDSA';

  const mockKeyPair = {
    jwks: { keys: [jwk] },
    publicKeys: { [KID]: publicKey },
    signJwt: async (jwtBuilder: SignJWT) => {
      return jwtBuilder
        .setProtectedHeader({ alg: 'EdDSA', kid: KID, typ: 'JWT' })
        .sign(privateKey);
    },
  };

  const mockFactory = {
    deriveEd25519KeyPair: vi.fn().mockResolvedValue(mockKeyPair),
  };

  vi.mocked(getPlatformCrypto).mockResolvedValue(mockFactory as any);
});

// --- Tests ---

describe('XTM Authentication', () => {
  // -- Pure helper tests --

  describe('isOwnIssuer', () => {
    it('should return true for the platform URL', () => {
      expect(isOwnIssuer(PLATFORM_URL)).toBe(true);
    });

    it('should return false for a different URL', () => {
      expect(isOwnIssuer('https://other.example.com')).toBe(false);
    });

    it('should return false for a trusted issuer URL', () => {
      expect(isOwnIssuer(TRUSTED_XTM_URL)).toBe(false);
    });
  });

  describe('isTrustedIssuer', () => {
    it('should return true for the configured trusted issuer', () => {
      expect(isTrustedIssuer(TRUSTED_XTM_URL)).toBe(true);
    });

    it('should return false for an unknown URL', () => {
      expect(isTrustedIssuer('https://unknown.example.com')).toBe(false);
    });

    it('should return false for the platform own URL', () => {
      expect(isTrustedIssuer(PLATFORM_URL)).toBe(false);
    });
  });

  // -- JWKS --

  describe('getXtmJwks', () => {
    it('should return the JWKS from the derived key pair', async () => {
      const jwks = await getXtmJwks();
      expect(jwks).toBeDefined();
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].kid).toBe(KID);
      expect(jwks.keys[0].alg).toBe('EdDSA');
    });
  });

  // -- JWT issuance --

  describe('issueXtmJwt', () => {
    it('should issue a valid three-part JWT string', async () => {
      const user = { id: 'user-123', user_email: 'test@example.com' };
      const token = await issueXtmJwt(user, 'https://audience.example.com');

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    it('should include correct claims in the JWT payload', async () => {
      const user = { id: 'user-456', user_email: 'user@test.com' };
      const audience = 'https://target.example.com';
      const token = await issueXtmJwt(user, audience);

      const [, payloadB64] = token.split('.');
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

      expect(payload.sub).toBe('user-456');
      expect(payload.email).toBe('user@test.com');
      expect(payload.iss).toBe(PLATFORM_URL);
      expect(payload.aud).toBe(audience);
      expect(payload.jti).toBeDefined();
      expect(payload.iat).toBeDefined();
      expect(payload.nbf).toBeDefined();
      expect(payload.exp).toBeDefined();
    });

    it('should set expiration based on the configured TTL (capped at 600s)', async () => {
      const user = { id: 'user-ttl', user_email: 'ttl@test.com' };
      const token = await issueXtmJwt(user, 'https://audience.example.com');

      const [, payloadB64] = token.split('.');
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

      // tokenTtl = Math.min(300, 600) = 300
      expect(payload.exp - payload.iat).toBe(300);
    });

    it('should generate unique JTI for each issued token', async () => {
      const user = { id: 'user-jti', user_email: 'jti@test.com' };
      const audience = 'https://audience.example.com';

      const token1 = await issueXtmJwt(user, audience);
      const token2 = await issueXtmJwt(user, audience);

      const decodePayload = (t: string) => {
        const [, payloadB64] = t.split('.');
        return JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
      };

      expect(decodePayload(token1).jti).not.toBe(decodePayload(token2).jti);
    });
  });

  // -- JWT verification --

  describe('verifyXtmJwt', () => {
    it('should verify a JWT issued by the platform (round-trip)', async () => {
      const user = { id: 'user-verify', user_email: 'verify@test.com' };
      const audience = 'https://audience.example.com';
      const token = await issueXtmJwt(user, audience);

      const result = await verifyXtmJwt(token);

      expect(result).toBeDefined();
      expect(result.payload.sub).toBe('user-verify');
      expect(result.payload.email).toBe('verify@test.com');
      expect(result.payload.iss).toBe(PLATFORM_URL);
      expect(result.payload.aud).toBe(audience);
    });

    it('should throw for an invalid/malformed token', async () => {
      await expect(verifyXtmJwt('not.a.valid-jwt'))
        .rejects.toThrow('JWT signature verification failed');
    });

    it('should throw when issuer is not trusted', async () => {
      const { privateKey } = await generateKeyPair('EdDSA');
      const token = await new SignJWT({ email: 'bad@test.com' })
        .setSubject('bad-user')
        .setIssuer('https://untrusted.example.com')
        .setAudience('https://audience.example.com')
        .setIssuedAt()
        .setExpirationTime('5m')
        .setProtectedHeader({ alg: 'EdDSA', kid: 'some-kid' })
        .sign(privateKey);

      await expect(verifyXtmJwt(token))
        .rejects.toThrow('JWT signature verification failed');
    });

    it('should throw when JWT has no iss claim', async () => {
      const { privateKey } = await generateKeyPair('EdDSA');
      const token = await new SignJWT({ email: 'no-iss@test.com' })
        .setSubject('no-iss-user')
        .setAudience('https://audience.example.com')
        .setIssuedAt()
        .setExpirationTime('5m')
        .setProtectedHeader({ alg: 'EdDSA', kid: 'no-iss-kid' })
        .sign(privateKey);

      await expect(verifyXtmJwt(token))
        .rejects.toThrow('JWT signature verification failed');
    });

    it('should throw when kid does not match any platform key', async () => {
      const { privateKey } = await generateKeyPair('EdDSA');
      const token = await new SignJWT({ email: 'wrong-kid@test.com' })
        .setSubject('wrong-kid-user')
        .setIssuer(PLATFORM_URL)
        .setAudience('https://audience.example.com')
        .setIssuedAt()
        .setExpirationTime('5m')
        .setProtectedHeader({ alg: 'EdDSA', kid: 'non-existent-kid' })
        .sign(privateKey);

      await expect(verifyXtmJwt(token))
        .rejects.toThrow('JWT signature verification failed');
    });

    it('should throw generic failure for a token signed with a different key', async () => {
      const { privateKey: wrongKey } = await generateKeyPair('EdDSA');
      const token = await new SignJWT({ email: 'tampered@test.com' })
        .setSubject('tampered-user')
        .setIssuer(PLATFORM_URL)
        .setAudience('https://audience.example.com')
        .setIssuedAt()
        .setExpirationTime('5m')
        .setProtectedHeader({ alg: 'EdDSA', kid: KID })
        .sign(wrongKey);

      await expect(verifyXtmJwt(token))
        .rejects.toThrow('JWT signature verification failed');
    });
  });
});
