import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elDeleteElements } from '../database/engine';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CAPABILITY, ENTITY_TYPE_ROLE } from '../schema/internalObject';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../schema/internalRelationship';
import { fullEntitiesList, fullRelationsList } from '../database/middleware-loader';

const message = '[MIGRATION] Remove INGESTION and INGESTION_SETINGESTIONS capabilities from Connector role';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const ingestionCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'INGESTION' });
  const manageIngestionCapabilityId = generateStandardId(ENTITY_TYPE_CAPABILITY, { name: 'INGESTION_SETINGESTIONS' });
  const connectorRoleId = generateStandardId(ENTITY_TYPE_ROLE, { name: 'Connector' });
  const deterministicCapabilityIds = [ingestionCapabilityId, manageIngestionCapabilityId];

  // Primary path: deterministic IDs for built-in role/capabilities.
  const directRelations = await fullRelationsList(context, SYSTEM_USER, RELATION_HAS_CAPABILITY, {
    fromId: connectorRoleId,
    toId: deterministicCapabilityIds,
  });
  const draftRelations = await fullRelationsList(context, SYSTEM_USER, RELATION_HAS_CAPABILITY_IN_DRAFT, {
    fromId: connectorRoleId,
    toId: deterministicCapabilityIds,
  });

  let relationsToDelete = [...directRelations, ...draftRelations];
  if (relationsToDelete.length > 0) {
    await elDeleteElements(context, SYSTEM_USER, relationsToDelete);
    logMigration.info(`${message} > removed ${relationsToDelete.length} relation(s) using deterministic IDs`);
  }

  // Fallback path for legacy/drifted data where IDs can differ.
  if (relationsToDelete.length === 0) {
    const capabilities = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_CAPABILITY]);
    const capabilityIds = capabilities
      .filter((c) => ['INGESTION', 'INGESTION_SETINGESTIONS'].includes(c.name))
      .map((c) => c.id);

    if (capabilityIds.length === 0) {
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
      const roleDirectRelations = await fullRelationsList(context, SYSTEM_USER, RELATION_HAS_CAPABILITY, {
        fromId: connectorRole.id,
      });
      const roleDraftRelations = await fullRelationsList(context, SYSTEM_USER, RELATION_HAS_CAPABILITY_IN_DRAFT, {
        fromId: connectorRole.id,
      });
      const roleRelationsToDelete = [
        ...roleDirectRelations.filter((r) => capabilityIds.includes(r.toId)),
        ...roleDraftRelations.filter((r) => capabilityIds.includes(r.toId)),
      ];

      if (roleRelationsToDelete.length > 0) {
        await elDeleteElements(context, SYSTEM_USER, roleRelationsToDelete);
        logMigration.info(`${message} > removed ${roleRelationsToDelete.length} relation(s) from role "${connectorRole.name}" (${connectorRole.id})`);
      } else {
        logMigration.info(`${message} > no ingestion relations found on role "${connectorRole.name}", skipping`);
      }
    }
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
