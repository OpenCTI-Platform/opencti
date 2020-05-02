import { tail } from 'ramda';
import { find, internalDirectWrite } from '../database/grakn';
import { logger } from '../config/conf';

export const up = async (next) => {
  const query = 'match $x isa MigrationStatus; get;';
  const result = await find(query, ['x']);
  if (result.length > 1) {
    await Promise.all(
      tail(result).map((migrationStatusEntity) => {
        const migrationStatus = migrationStatusEntity.x;
        const deleteQuery = `match $x id ${migrationStatus.grakn_id}; $z($x, $y); delete $z, $x;`;
        logger.info(`[MIGRATION] delete_extra_migration_status`, { query: deleteQuery });
        return internalDirectWrite(deleteQuery);
      })
    );
  }
  next();
};

export const down = async (next) => {
  next();
};
