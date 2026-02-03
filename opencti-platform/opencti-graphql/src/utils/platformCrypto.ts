import crypto from 'crypto';
import nconf from 'nconf';
import { promisify } from 'util';
import * as ed25519 from '@noble/ed25519'; // required for ed25519 key derivation from seed, not available in crypto module
import { importJWK, type JWK, jwtVerify, SignJWT } from 'jose';
import { enrichWithRemoteCredentials } from '../config/credentials';

const hkdfAsync = promisify(crypto.hkdf);

const masterSeedConfName = 'app:crypto:master_seed';
const zeroBuffer = Buffer.alloc(0);

export const createCryptoKeyFactory = (seed: Buffer) => {
  if (seed.length < 32) {
    throw new Error(`${masterSeedConfName} must decode to at least 32 bytes`);
  }

  const b64 = (buf: Uint8Array | Buffer) => Buffer.from(buf).toString('base64');
  const b64Url = (u8: Uint8Array | Buffer) =>
    Buffer.from(u8).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const fromB64 = (s: string) => Buffer.from(s, 'base64');

  const deriveBytes = async (
    derivationPath: string[],
    version: number,
    length: number,
  ): Promise<Buffer> => {
    if (!(derivationPath.length > 0 && derivationPath.every((s) => s !== '' && !s.includes(':')))) {
      throw new Error('invalid derivation path');
    }

    if (version <= 0) {
      throw new Error('version must be positive');
    }

    if (length <= 0) {
      throw new Error('length must be positive');
    }

    const fullDerivationPath = `${derivationPath.join(':')}::v${version}`;
    const derivationBytes = Buffer.from(fullDerivationPath);

    const out = await hkdfAsync('sha256', seed, zeroBuffer, derivationBytes, length);
    return Buffer.from(out);
  };

  const deriveKid = async (
    derivationPath: string[],
    version: number,
  ) => {
    const material = await deriveBytes(derivationPath, version, 32);

    return crypto
      .createHash('sha256')
      .update(material)
      .digest('hex')
      .slice(0, 16);
  };

  const deriveAesKey = async (
    derivationPath: string[],
    version: number,
    bits: 128 | 192 | 256 = 256,
    aad?: string | undefined,
  ) => {
    const aesKey = await deriveBytes([...derivationPath, `aes-${bits}`, 'key'], version, bits / 8);
    const aesKeyId = await deriveKid([...derivationPath, `aes-${bits}`, 'kid'], version);
    const algo = `aes-${bits}-gcm` as const;
    const aadBuffer = aad !== undefined ? Buffer.from(aad) : undefined;

    const encrypt = async (data: string) => {
      const iv = crypto.randomBytes(12); // recommended nonce size for GCM
      const cipher = crypto.createCipheriv(algo, aesKey, iv);
      if (aadBuffer !== undefined) {
        cipher.setAAD(aadBuffer);
      }

      const encryptedData = Buffer.concat([
        cipher.update(Buffer.from(data)),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      return {
        kid: aesKeyId,
        data: `${b64(iv)}.${b64(encryptedData)}.${b64(tag)}`,
      };
    };

    const decrypt = async (kid: string, data: string): Promise<string> => {
      if (kid !== aesKeyId) {
        throw new Error('invalid kid for decryption');
      }

      const raw = data.split('.');
      if (raw.length !== 3) {
        throw new Error('invalid encrypted data format');
      }

      const iv = fromB64(raw[0]);
      const ct = fromB64(raw[1]);
      const tag = fromB64(raw[2]);

      const decipher = crypto.createDecipheriv(algo, aesKey, iv);
      decipher.setAuthTag(tag);
      if (aadBuffer !== undefined) {
        decipher.setAAD(aadBuffer);
      }

      return Buffer.concat([decipher.update(ct), decipher.final()]).toString();
    };

    return { encrypt, decrypt };
  };

  const deriveEd25519KeyPair = async (
    derivationPath: string[],
    version: number,
  ) => {
    const seed32 = await deriveBytes([...derivationPath, 'ed25519', 'seed'], version, 32);
    const ed25519KeyId = await deriveKid([...derivationPath, 'ed25519', 'kid'], version);
    const publicKey = await ed25519.getPublicKeyAsync(seed32);

    const jwkPublic: JWK = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: b64Url(publicKey),
      kid: ed25519KeyId,
      use: 'sig',
      alg: 'EdDSA',
    };
    const publicJWK = await importJWK(jwkPublic, 'EdDSA');
    const privateJWK = await importJWK({ ...jwkPublic, d: b64Url(seed32) }, 'EdDSA');

    const signJwt = async (signJwt: SignJWT) => {
      return await signJwt.setProtectedHeader({ alg: 'EdDSA', kid: ed25519KeyId }).sign(privateJWK);
    };

    const verifyJwt = async (token: string) => {
      return jwtVerify(token, publicJWK);
    };

    const sign = async (data: string) => {
      const signature = await ed25519.signAsync(Buffer.from(data), seed32);
      return { kid: ed25519KeyId, signature: b64(signature) };
    };

    const verify = async (kid: string, signature: string, data: string) => {
      if (kid !== ed25519KeyId) {
        throw new Error('invalid kid for verification');
      }
      return await ed25519.verifyAsync(fromB64(signature), Buffer.from(data), publicKey);
    };

    return {
      kid: ed25519KeyId,
      publicKey,
      signJwt,
      verifyJwt,
      sign,
      verify,
    };
  };

  return {
    deriveAesKey,
    deriveEd25519KeyPair,
  };
};

const createPlatformCrypto = async () => {
  const seedConfValue = nconf.get(masterSeedConfName);
  if (!seedConfValue) {
    throw new Error(`${masterSeedConfName} configuration is missing`);
  }

  const { master_seed } = await enrichWithRemoteCredentials('crypto', { master_seed: seedConfValue });
  return createCryptoKeyFactory(master_seed);
};

let platformCryptoPromise: Promise<ReturnType<typeof createCryptoKeyFactory>> | undefined = undefined;

export const getPlatformCrypto = async () => {
  if (!platformCryptoPromise) {
    platformCryptoPromise = createPlatformCrypto();
  }
  return platformCryptoPromise;
};
