import '../src/modules/index';
import { cleanInconsistentRelations } from '../src/utils/clean-relations';
import { logApp } from '../src/config/conf';
import { executionContext } from '../src/utils/access';

const context = executionContext('script');
await cleanInconsistentRelations(context);
logApp.info('[SCRIPT] Clean relations done');
