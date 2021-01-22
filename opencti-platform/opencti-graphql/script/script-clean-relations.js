import { cleanInconsistentRelations } from '../src/utils/clean-relations';
import { logger } from '../src/config/conf';

cleanInconsistentRelations().then(() => logger.info(`[SCRIPT] Clean relations done`));
