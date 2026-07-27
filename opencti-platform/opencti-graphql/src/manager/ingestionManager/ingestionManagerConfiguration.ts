import conf from '../../config/conf';

export const INGESTION_MANAGER_SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 30000;
