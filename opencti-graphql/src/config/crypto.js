import Crypto from 'crypto';
import conf from './conf';

const CRYPTO_ALGORITHM = 'aes-256-cbc';

export const encrypt = data => {
  const cipher = Crypto.createCipher(CRYPTO_ALGORITHM, conf.get('jwt:secret'));
  const encrypted = Buffer.concat([
    cipher.update(data.toString()),
    cipher.final()
  ]);
  return encrypted.toString('base64');
};

export const decrypt = data => {
  const decipher = Crypto.createDecipher(
    CRYPTO_ALGORITHM,
    conf.get('jwt:secret')
  );
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(data, 'base64')),
    decipher.final()
  ]);
  return decrypted.toString();
};
