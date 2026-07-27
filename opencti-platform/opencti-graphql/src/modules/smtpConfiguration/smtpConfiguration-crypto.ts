import { decryptValue, encryptValue, getPlatformCrypto } from '../../utils/platformCrypto';
import { memoize } from '../../utils/memoize';

// Shared derivation path — used both when writing secrets to the store
// (smtpConfiguration-domain.ts) and when reading them back to build the
// nodemailer transporter (database/smtp.js). Keeping it in a single module
// avoids any risk of the two call sites drifting apart, which would
// otherwise silently break decryption.
const getSmtpKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveAesKey(['smtp', 'elastic'], 1);
});

export const encryptSmtpSecret = async (value: string | undefined | null) => encryptValue(await getSmtpKeyPair(), value);

export const decryptSmtpSecret = async (value: string | undefined | null) => decryptValue(await getSmtpKeyPair(), value);
