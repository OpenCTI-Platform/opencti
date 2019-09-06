import { find, updateAttribute } from '../database/grakn';
import { logger } from '../config/conf';

module.exports.up = async next => {
  const resultPromise = Promise.all(
    ['sector', 'organization', 'user', 'region', 'country', 'city'].map(
      async entityType => {
        const query = `match $x isa entity; $x has stix_id $sid; $sid contains "${entityType}"; get $x;`;
        const entities = await find(query, ['x']);
        logger.info('[MIGRATION] update-stix_id > Entities loaded');
        const updatePromise = Promise.all(
          entities.map(entity => {
            return updateAttribute(entity.x.id, {
              key: 'stix_id',
              value: [entity.x.stix_id.replace(entityType, 'identity')]
            });
          })
        );
        await Promise.resolve(updatePromise).then(() => {
          logger.info('[MIGRATION] update-stix_id > Entities updated');
          return Promise.resolve(true);
        });
      }
    )
  );
  await Promise.resolve(resultPromise).then(() => {
    logger.info('[MIGRATION] update-stix_id > Migration complete');
  });
  next();
};

module.exports.down = async next => {
  next();
};
