import conf from '../../config/conf';
import { uriDenyList } from '../../config/uriDenyList';

// Backward compatibility for existing tests/mocks that still target ingestion config module.
export const ingestionUriDenyList = uriDenyList;

export const INGESTION_MANAGER_SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 30000;
