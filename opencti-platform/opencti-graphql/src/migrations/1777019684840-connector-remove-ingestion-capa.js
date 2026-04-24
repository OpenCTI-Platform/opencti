import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elDeleteElements } from '../database/engine';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../schema/internalRelationship';
import { fullEntitiesList, fullRelationsList } from '../database/middleware-loader';

const message = '[MIGRATION] Remove INGESTION and INGESTION_SETINGESTIONS capabilities from Connector role';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // Resolve capability internal IDs by name (do NOT use generateStandardId — toId stores internal id)
  const capabilities = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_CAPABILITY]);
  const ingestionCapabilities = capabilities.filter((c) =>
    ['INGESTION', 'INGESTION_SETINGESTIONS'].includes(c.name),
  );
  const capabilityInternalIds = ingestionCapabilities.map((c) => c.id);

  if (capabilityInternalIds.length === 0) {
    logMigration.info(`${message} > INGESTION capabilities not found in database, skipping`);
    next();
    return;
  }

  const roles = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_ROLE]);
  const connectorRoles = roles.filter((role) => role.name === 'Connector');

  if (connectorRoles.length === 0) {
    logMigration.info(`${message} > no Connector role found, skipping`);
    next();
    return;
  }

  for (const connectorRole of connectorRoles) {
    // delete standard has-capability relations
    const relations = await fullRelationsList(context, SYSTEM_USER, RELATION_HAS_CAPABILITY, {
      fromId: connectorRole.id,
    });
    const toDelete = relations.filter((r) => capabilityInternalIds.includes(r.toId));
    if (toDelete.length > 0) {
      await elDeleteElements(context, SYSTEM_USER, toDelete);
      logMigration.info(`${message} > removed ${toDelete.length} has-capability relation(s) from role "${connectorRole.name}" (${connectorRole.id})`);
    } else {
      logMigration.info(`${message} > no INGESTION has-capability relations found on role "${connectorRole.name}", skipping`);
    }

    // delete draft has-capability-in-draft relations
    const draftRelations = await fullRelationsList(context, SYSTEM_USER, RELATION_HAS_CAPABILITY_IN_DRAFT, {
      fromId: connectorRole.id,
    });
    const draftToDelete = draftRelations.filter((r) => capabilityInternalIds.includes(r.toId));
    if (draftToDelete.length > 0) {
      await elDeleteElements(context, SYSTEM_USER, draftToDelete);
      logMigration.info(`${message} > removed ${draftToDelete.length} has-capability-in-draft relation(s) from role "${connectorRole.name}" (${connectorRole.id})`);
    } else {
      logMigration.info(`${message} > no INGESTION has-capability-in-draft relations found on role "${connectorRole.name}", skipping`);
    }
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
