var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { v4 as uuid } from 'uuid';
import conf, { logApp } from '../config/conf';
import historyManager from './historyManager';
import ruleEngine from './ruleManager';
import taskManager from './taskManager';
import expiredManager from './expiredManager';
import syncManager from './syncManager';
import retentionManager from './retentionManager';
import publisherManager from './publisherManager';
import notificationManager from './notificationManager';
import ingestionManager from './ingestionManager';
import activityManager from './activityManager';
import fileIndexManager from './fileIndexManager';
import { registerClusterInstance } from '../database/redis';
import { getEntityFromCache } from '../database/cache';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import playbookManager from './playbookManager';
import { getAllManagersStatuses } from './managerModule';
const SCHEDULE_TIME = 30000;
const NODE_INSTANCE_ID = conf.get('app:node_identifier') || uuid();
const initClusterManager = () => {
    let scheduler;
    const clusterHandler = (platformId) => __awaiter(void 0, void 0, void 0, function* () {
        const context = executionContext('cluster_manager');
        const settings = yield getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
        // TODO migrate managers modules
        const managers = [
            ruleEngine.status(),
            historyManager.status(),
            taskManager.status(),
            expiredManager.status(),
            syncManager.status(),
            retentionManager.status(),
            publisherManager.status(),
            notificationManager.status(),
            ingestionManager.status(),
            activityManager.status(settings),
            playbookManager.status(settings),
            fileIndexManager.status(settings),
            ...getAllManagersStatuses(),
        ];
        const configData = { platform_id: platformId, managers };
        yield registerClusterInstance(platformId, configData);
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Starting cluster manager');
            const platformId = `platform:instance:${NODE_INSTANCE_ID}`;
            yield clusterHandler(platformId);
            // receive information from the managers every 30s
            scheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield clusterHandler(platformId);
            }), SCHEDULE_TIME);
        }),
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping cluster manager');
            if (scheduler) {
                yield clearIntervalAsync(scheduler);
            }
            return true;
        }),
    };
};
const clusterManager = initClusterManager();
export default clusterManager;
