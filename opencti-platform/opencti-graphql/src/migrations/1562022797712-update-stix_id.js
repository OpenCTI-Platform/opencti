import { executeWrite, find, updateAttribute } from '../database/grakn';
import { logger } from '../config/conf';

export const up = async (next) => {
  await Promise.all(
    ['sector', 'organization', 'user', 'region', 'country', 'city'].map(async (entityType) => {
      const query = `match $x isa entity; $x has stix_id_key $sid; $sid contains "${entityType}"; get;`;
      const entities = await find(query, ['x']);
      logger.info('[MIGRATION] update-stix_id_key > Entities loaded');
      await Promise.all(
        entities.map((entity) => {
          return executeWrite((wTx) => {
            return updateAttribute(
              entity.x.id,
              'Identity',
              {
                key: 'stix_id_key',
                value: [entity.x.stix_id_key.replace(entityType, 'identity')],
              },
              wTx
            );
          });
        })
      );
      logger.info('[MIGRATION] update-stix_id_key > Entities updated');
      return true;
    })
  );
  logger.info('[MIGRATION] update-stix_id_key > Migration complete');
  next();
};

export const down = async (next) => {
  next();
};
