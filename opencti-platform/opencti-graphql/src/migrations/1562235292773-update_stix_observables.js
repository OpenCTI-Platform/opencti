import { executeWrite, find, updateAttribute } from '../database/grakn';
import { logger } from '../config/conf';

export const up = async (next) => {
  await Promise.all(
    ['observable'].map(async (entityType) => {
      const query = `match $x isa entity; $x has stix_id_key $sid; $sid contains "${entityType}"; get;`;
      const entities = await find(query, ['x']);
      logger.info('[MIGRATION] update-stix_observables > Entities loaded');
      await Promise.all(
        entities.map((entity) => {
          return executeWrite((wTx) => {
            return updateAttribute(
              entity.x.id,
              'Stix-Observable',
              {
                key: 'stix_id_key',
                value: [entity.x.stix_id_key.replace(entityType, 'indicator')],
              },
              wTx
            );
          });
        })
      );
      logger.info('[MIGRATION] update-stix_observables > Entities updated');
      return true;
    })
  );
  logger.info('[MIGRATION] update-stix_observables > Migration complete');
  next();
};

export const down = async (next) => {
  next();
};
