import { tail } from 'ramda';
import { find, write } from '../database/grakn';
import { logger } from '../config/conf';

module.exports.up = async next => {
  const query = 'match $x isa MigrationStatus; get;';
  const result = await find(query, ['x']);
  if (result.length > 1) {
    await Promise.all(
      tail(result).map(migrationStatusEntity => {
        const migrationStatus = migrationStatusEntity.x;
        const deleteQuery = `match $x id ${migrationStatus.grakn_id}; $z($x, $y); delete $z, $x;`;
        logger.info(
          `[MIGRATION] delete_extra_migration_status > ${deleteQuery}`
        );
        return write(deleteQuery);
      })
    );
  }
  next();
};

module.exports.down = async next => {
  next();
};
