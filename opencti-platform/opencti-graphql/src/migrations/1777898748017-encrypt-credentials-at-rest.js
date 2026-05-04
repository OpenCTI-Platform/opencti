import { logMigration } from '../config/conf';
import { fullEntitiesOrRelationsList } from '../database/middleware';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_TAXII } from '../modules/ingestion/ingestion-types';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { encryptDatabaseValue, getPlatformCrypto } from '../utils/platformCrypto';
import { elUpdate } from '../database/engine';

const message = '[MIGRATION] Encrypt credentials at rest for ingestions and synchronizers';

/**
 * Try to decrypt a value to check if it's already encrypted.
 * Returns true if the value is already encrypted (decryption succeeded).
 * Returns false if decryption failed, meaning the value is plain text and should be encrypted.
 */
const isAlreadyEncrypted = async (keyPair, value) => {
  try {
    await keyPair.decrypt(Buffer.from(value, 'base64'));
    return true;
  } catch {
    return false;
  }
};

const encryptFieldIfNeeded = async (keyPair, entity, fieldName) => {
  const value = entity[fieldName];
  if (!value) return;
  const alreadyEncrypted = await isAlreadyEncrypted(keyPair, value);
  if (alreadyEncrypted) return;
  const encrypted = await encryptDatabaseValue(value);
  await elUpdate(entity._index, entity.internal_id, { doc: { [fieldName]: encrypted } });
};

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const factory = await getPlatformCrypto();
  const keyPair = await factory.deriveAesKey(['general', 'credentials'], 1);

  // -- IngestionCsv --
  const csvIngestions = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_CSV]);
  logMigration.info(`${message} > found ${csvIngestions.length} CSV ingestions`);
  for (let i = 0; i < csvIngestions.length; i += 1) {
    await encryptFieldIfNeeded(keyPair, csvIngestions[i], 'authentication_value');
  }

  // -- IngestionJson --
  const jsonIngestions = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_JSON]);
  logMigration.info(`${message} > found ${jsonIngestions.length} JSON ingestions`);
  for (let i = 0; i < jsonIngestions.length; i += 1) {
    await encryptFieldIfNeeded(keyPair, jsonIngestions[i], 'authentication_value');
  }

  // -- IngestionTaxii --
  const taxiiIngestions = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_TAXII]);
  logMigration.info(`${message} > found ${taxiiIngestions.length} TAXII ingestions`);
  for (let i = 0; i < taxiiIngestions.length; i += 1) {
    await encryptFieldIfNeeded(keyPair, taxiiIngestions[i], 'authentication_value');
  }

  // -- Synchronizer --
  const synchronizers = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_SYNC]);
  logMigration.info(`${message} > found ${synchronizers.length} synchronizers`);
  for (let i = 0; i < synchronizers.length; i += 1) {
    await encryptFieldIfNeeded(keyPair, synchronizers[i], 'token');
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
