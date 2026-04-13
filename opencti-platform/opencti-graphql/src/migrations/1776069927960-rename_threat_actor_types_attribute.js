import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Rename threat_actor_types attribute to threat_actor_group_types and threat_actor_individual_types';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  // Threat Actor Group
  const updateQuery_threatActorGroup = {
    script: {
      source: "if (!ctx._source.containsKey('threat_actor_group_types')) { ctx._source.threat_actor_group_types = ctx._source.threat_actor_types; ctx._source.remove('threat_actor_types'); }",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Threat-Actor-Group' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Renaming threat_actor_types attribute into threat_actor_group_types for Threat Actor Group',
    [READ_INDEX_STIX_DOMAIN_OBJECTS],
    updateQuery_threatActorGroup,
  );

  // Threat Actor Group
  const updateQuery_threatActorIndividual = {
    script: {
      source: "if (!ctx._source.containsKey('threat_actor_individual_types')) { ctx._source.threat_actor_individual_types = ctx._source.threat_actor_types; ctx._source.remove('threat_actor_types'); }",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Threat-Actor-Individual' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Renaming threat_actor_types attribute into threat_actor_individual_types for Threat Actor Indivudal',
    [READ_INDEX_STIX_DOMAIN_OBJECTS],
    updateQuery_threatActorIndividual,
  );
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
