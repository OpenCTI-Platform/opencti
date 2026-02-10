import crypto from 'crypto';
import nconf from 'nconf';
import { promisify } from 'util';
import * as ed25519 from '@noble/ed25519'; // required for ed25519 key derivation from seed, not available in crypto module
import type { JWTVerifyOptions } from 'jose';
import { importJWK, type JWK, jwtVerify, SignJWT } from 'jose';
import { enrichWithRemoteCredentials } from '../config/credentials';
import { confNameToEnvName } from '../config/conf';
import { ConfigurationError, UnsupportedError } from '../config/errors';

export const JWT_TOKEN_PREFIX = 'ey';
const hkdfAsync = promisify(crypto.hkdf);
const toHex = (buffer: Buffer) => buffer.toString('hex');
const zeroBuffer = Buffer.alloc(0);

export const createCryptoKeyFactory = (seed: Buffer) => {
  if (seed.length < 32) {
    throw ConfigurationError('Seed must have at least 32 bytes', { seedLength: seed.length });
  }

  const deriveBytes = async (
    derivationPath: string[],
    derivationPathVersion: number,
    length: number,
  ): Promise<Buffer> => {
    if (!(derivationPath.length > 0 && derivationPath.every((s) => s !== '' && !s.includes(':')))) {
      throw UnsupportedError('Invalid derivation path', { derivationPath });
    }

    if (derivationPathVersion <= 0) {
      throw UnsupportedError('Version must be positive', { version: derivationPathVersion });
    }

    if (length <= 0) {
      throw UnsupportedError('Length must be positive', { length });
    }

    const fullDerivationPath = `${derivationPath.join(':')}::v${derivationPathVersion}`;
    const out = await hkdfAsync('sha256', seed, zeroBuffer, Buffer.from(fullDerivationPath), length);
    return Buffer.from(out);
  };

  const kidLength = 8;
  const deriveKid = async (
    derivationPath: string[],
    version: number,
  ): Promise<Buffer> => {
    const material = await deriveBytes(derivationPath, version, 32);

    return crypto
      .createHash('sha256')
      .update(material)
      .digest()
      .subarray(0, kidLength);
  };

  const deriveAesKey = async (
    derivationPath: string[],
    derivationPathVersion: number,
  ) => {
    const encodingVersion = 0x01;
    const ivLength = 12;
    const authTagLength = 16;
    const minLength = 1 + kidLength + ivLength + authTagLength;

    const bits = 256;
    const algo = `aes-${bits}-gcm` as const;
    const key = await deriveBytes([...derivationPath, algo, 'key'], derivationPathVersion, bits / 8);
    const kid = await deriveKid([...derivationPath, algo, 'kid'], derivationPathVersion);

    const encrypt = async (data: Buffer, aad?: Buffer | undefined) => {
      const iv = crypto.randomBytes(ivLength); // recommended nonce size for GCM
      const cipher = crypto.createCipheriv(algo, key, iv, { authTagLength });
      if (aad !== undefined) {
        cipher.setAAD(aad);
      }

      const encryptedData = Buffer.concat([
        cipher.update(data),
        cipher.final(),
      ]);
      const authTag = cipher.getAuthTag();

      // kid needs to be stored with encrypted data to allow multiple keys usage (e.g. key rotation)
      return Buffer.concat([Buffer.from([encodingVersion]), kid, iv, authTag, encryptedData]);
    };

    const decrypt = async (data: Buffer, aad?: Buffer | undefined) => {
      const receivedLength = data.length;
      if (data.length < minLength) {
        throw UnsupportedError('Unsupported encrypted data', { expectedMinimumLength: minLength, receivedLength });
      }

      let i = 0;
      const receivedVersion = data[i++];
      if (receivedVersion !== encodingVersion) {
        throw UnsupportedError('Unsupported encrypted data encoding version', { expectedVersion: encodingVersion, receivedVersion });
      }

      const receivedKid = data.subarray(i, i + kid.length);
      i += kid.length;
      if (!receivedKid.equals(kid)) {
        throw UnsupportedError('Invalid kid for decryption', { expectedKid: toHex(kid), receivedKid: toHex(receivedKid) });
      }

      const iv = data.subarray(i, i + ivLength);
      i += ivLength;
      const tag = data.subarray(i, i + authTagLength);
      i += authTagLength;
      const ct = data.subarray(i);

      const decipher = crypto.createDecipheriv(algo, key, iv);
      decipher.setAuthTag(tag);
      if (aad !== undefined) {
        decipher.setAAD(aad);
      }

      return Buffer.concat([decipher.update(ct), decipher.final()]);
    };

    return {
      encrypt,
      decrypt,
    };
  };

  const deriveEd25519KeyPair = async (
    derivationPath: string[],
    version: number,
  ) => {
    const seed32 = await deriveBytes([...derivationPath, 'ed25519', 'seed'], version, 32);
    const kid = await deriveKid([...derivationPath, 'ed25519', 'kid'], version);
    const publicKey = await ed25519.getPublicKeyAsync(seed32);

    const encodingVersion = 0x01;
    const minLength = 1 + kidLength;

    const sign = async (data: Buffer) => {
      const signature = await ed25519.signAsync(data, seed32);
      // kid needs to be stored with encrypted data to allow multiple keys usage (e.g. key rotation)
      return Buffer.concat([Buffer.from([encodingVersion]), kid, signature]);
    };

    const verify = async (data: Buffer, signature: Buffer) => {
      const receivedLength = signature.length;
      if (signature.length < minLength) {
        throw UnsupportedError('Invalid signature format', { expectedMinimumLength: minLength, receivedLength });
      }

      let i = 0;
      const receivedVersion = signature[i++];
      if (receivedVersion !== encodingVersion) {
        throw UnsupportedError('Unsupported signature encoding version', { expectedVersion: encodingVersion, receivedVersion });
      }

      const receivedKid = signature.subarray(i, i + kid.length);
      i += kid.length;
      if (!receivedKid.equals(kid)) {
        throw UnsupportedError('Invalid kid for signature verification', { expectedKid: toHex(kid), receivedKid: toHex(receivedKid) });
      }

      return await ed25519.verifyAsync(signature.subarray(i), data, publicKey);
    };

    const jwk = {
      kid: toHex(kid),
      use: 'sig',
      alg: 'EdDSA',
      crv: 'Ed25519',
      kty: 'OKP',
      x: Buffer.from(publicKey).toString('base64url'),
    } satisfies JWK;

    const publicJWK = await importJWK(jwk);
    const privateJWK = await importJWK({
      ...jwk,
      d: Buffer.from(seed32).toString('base64url'),
    });

    const signJwt = async (jwt: SignJWT) => {
      return await jwt.setProtectedHeader({ kid: jwk.kid, alg: jwk.alg }).sign(privateJWK);
    };

    const verifyJwt = async (token: string | Uint8Array, options?: JWTVerifyOptions) => {
      return jwtVerify(token, publicJWK, options);
    };

    return {
      publicKeys: {
        [toHex(kid)]: publicKey,
      },
      jwks: {
        [toHex(kid)]: jwk,
      },
      sign,
      verify,
      signJwt,
      verifyJwt,
    };
  };

  const deriveHmac = async (
    derivationPath: string[],
    version: number,
  ) => {
    const bits = 256;
    const hashAlgo = `sha${bits}` as const;
    const key = await deriveBytes([...derivationPath, `hmac-${hashAlgo}`], version, 32);

    const hmac = (data: string): string => {
      return crypto.createHmac(hashAlgo, key).update(data, 'utf-8').digest('base64');
    };

    return {
      hmac,
    };
  };

  return {
    deriveAesKey,
    deriveHmac,
    deriveEd25519KeyPair,
  };
};

// best effort to handle safely the environment variable containing the master seed, remove it from env after reading so it cannot be leaked to spawned processes
// buffer will be cleaned when read
const masterSeedConfName = 'app:crypto:master_seed';
const masterSeedEnvBuffer = Buffer.from(nconf.get(masterSeedConfName) ?? '', 'base64');
delete process.env[confNameToEnvName(masterSeedConfName)];

const createPlatformCrypto = async () => {
  const { master_seed } = await enrichWithRemoteCredentials('crypto', {});
  const seed = master_seed ? Buffer.from(master_seed, 'base64') : masterSeedEnvBuffer;

  if (seed.length < 32) {
    throw ConfigurationError(`${masterSeedConfName} configuration is missing or invalid, please provide at least 32 bytes of base64-encoded data by using 'openssl rand -base64 32' command`, { seedLength: seed.length });
  }

  const promise = createCryptoKeyFactory(Buffer.from(seed)); // send a private copy of the seed
  seed.fill(0); // clean the local seed buffer
  masterSeedEnvBuffer.fill(0); // always clean the buffer containing the master seed from env
  return promise;
};

let platformCryptoPromise: Promise<ReturnType<typeof createCryptoKeyFactory>> | undefined = undefined;

export const getPlatformCrypto = async () => {
  if (!platformCryptoPromise) {
    platformCryptoPromise = createPlatformCrypto();
  }
  return platformCryptoPromise;
};
