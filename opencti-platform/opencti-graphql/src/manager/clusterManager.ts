import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { logApp } from '../config/conf';
import historyManager from './historyManager';

const SCHEDULE_TIME = 30000;

const initClusterManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  let syncListening = true;
  const clusterHandler = async () => {
    try {
      logApp.info('[OPENCTI-MODULE] hello'); // printing Hello every 30s
    } finally { /* empty */ }
  };
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting cluster manager');
      await historyManager.declare();
      scheduler = setIntervalAsync(async () => {
        await clusterHandler();
      }, SCHEDULE_TIME);
    },
    shutdown: async () => {
      syncListening = false;
      logApp.info('[OPENCTI-MODULE] Stopping cluster manager');
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const clusterManager = initClusterManager();

export default clusterManager;
