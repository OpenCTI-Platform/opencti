import { decryptValue, encryptValue, getPlatformCrypto } from '../utils/platformCrypto';
import { memoize } from '../utils/memoize';

export const getSynchronizerKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveAesKey(['synchronizer', 'credentials'], 1);
});

export const encryptSynchronizerCredential = async (value: string | undefined | null) => {
  return encryptValue(await getSynchronizerKeyPair(), value);
};

export const decryptSynchronizerCredential = async (value: string | undefined | null) => {
  return decryptValue(await getSynchronizerKeyPair(), value);
};

export const isSynchronizerCredentialEncrypted = async (value: string): Promise<boolean> => {
  try {
    const keyPair = await getSynchronizerKeyPair();
    await keyPair.decrypt(Buffer.from(value, 'base64'));
    return true;
  } catch {
    return false;
  }
};
