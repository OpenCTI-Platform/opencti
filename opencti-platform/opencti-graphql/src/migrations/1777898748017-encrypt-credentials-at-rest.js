import { logMigration } from '../config/conf';
import { fullEntitiesOrRelationsList } from '../database/middleware';
import { ENTITY_TYPE_SYNC } from '../schema/internalObject';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_TAXII } from '../modules/ingestion/ingestion-types';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { encryptIngestionCredential, encryptSynchronizerCredential, isIngestionCredentialEncrypted, isSynchronizerCredentialEncrypted } from '../utils/platformCrypto';
import { elUpdate } from '../database/engine';

const message = '[MIGRATION] Encrypt credentials at rest for ingestions and synchronizers';

const encryptIngestionFieldIfNeeded = async (entity, fieldName) => {
  const value = entity[fieldName];
  if (!value) return;
  if (await isIngestionCredentialEncrypted(value)) return;
  const encrypted = await encryptIngestionCredential(value);
  await elUpdate(entity._index, entity.internal_id, { doc: { [fieldName]: encrypted } });
};

const encryptSynchronizerFieldIfNeeded = async (entity, fieldName) => {
  const value = entity[fieldName];
  if (!value) return;
  if (await isSynchronizerCredentialEncrypted(value)) return;
  const encrypted = await encryptSynchronizerCredential(value);
  await elUpdate(entity._index, entity.internal_id, { doc: { [fieldName]: encrypted } });
};

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // -- IngestionCsv --
  const csvIngestions = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_CSV]);
  logMigration.info(`${message} > found ${csvIngestions.length} CSV ingestions`);
  for (let i = 0; i < csvIngestions.length; i += 1) {
    await encryptIngestionFieldIfNeeded(csvIngestions[i], 'authentication_value');
  }

  // -- IngestionJson --
  const jsonIngestions = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_JSON]);
  logMigration.info(`${message} > found ${jsonIngestions.length} JSON ingestions`);
  for (let i = 0; i < jsonIngestions.length; i += 1) {
    await encryptIngestionFieldIfNeeded(jsonIngestions[i], 'authentication_value');
  }

  // -- IngestionTaxii --
  const taxiiIngestions = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_TAXII]);
  logMigration.info(`${message} > found ${taxiiIngestions.length} TAXII ingestions`);
  for (let i = 0; i < taxiiIngestions.length; i += 1) {
    await encryptIngestionFieldIfNeeded(taxiiIngestions[i], 'authentication_value');
  }

  // -- Synchronizer --
  const synchronizers = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_SYNC]);
  logMigration.info(`${message} > found ${synchronizers.length} synchronizers`);
  for (let i = 0; i < synchronizers.length; i += 1) {
    await encryptSynchronizerFieldIfNeeded(synchronizers[i], 'token');
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
