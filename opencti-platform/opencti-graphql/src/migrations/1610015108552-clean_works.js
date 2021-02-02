import { connectors } from '../domain/connector';
import { deleteOldCompletedWorks } from '../domain/work';
import { logger } from '../config/conf';
import { SYSTEM_USER } from '../domain/user';

export const up = async (next) => {
  const connectorList = await connectors(SYSTEM_USER);
  for (let index = 0; index < connectorList.length; index += 1) {
    const connector = connectorList[index];
    logger.info(`Deleting old works for ${connector.name}`);
    await deleteOldCompletedWorks(connector, true);
  }
  next();
};

export const down = async (next) => {
  next();
};
