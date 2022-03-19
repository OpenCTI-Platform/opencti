import { cleanInconsistentRelations } from '../src/utils/clean-relations';
import { logApp } from '../src/config/conf';

cleanInconsistentRelations().then(() => logApp.info('[SCRIPT] Clean relations done'));
