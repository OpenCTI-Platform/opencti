import { find, updateAttribute } from '../database/grakn';
import { logger } from '../config/conf';

module.exports.up = async next => {
  const resultPromise = Promise.all(
    ['observable'].map(async entityType => {
      const query = `match $x isa entity; $x has stix_id $sid; $sid contains "${entityType}"; get $x;`;
      const entities = await find(query, ['x']);
      logger.info('[MIGRATION] update-stix_observables > Entities loaded');
      const updatePromise = Promise.all(
        entities.map(entity => {
          return updateAttribute(entity.x.id, {
            key: 'stix_id',
            value: [entity.x.stix_id.replace(entityType, 'indicator')]
          });
        })
      );
      await Promise.resolve(updatePromise).then(() => {
        logger.info('[MIGRATION] update-stix_observables > Entities updated');
        return Promise.resolve(true);
      });
    })
  );
  await Promise.resolve(resultPromise).then(() => {
    logger.info('[MIGRATION] update-stix_observables > Migration complete');
  });
  next();
};

module.exports.down = async next => {
  next();
};
