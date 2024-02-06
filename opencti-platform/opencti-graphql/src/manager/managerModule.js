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
import moment from 'moment/moment';
import { createStreamProcessor, lockResource } from '../database/redis';
import { logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { SYSTEM_USER } from '../utils/access';
import { utcDate } from '../utils/format';
const initManager = (manager) => {
    const WAIT_TIME_ACTION = 2000;
    let scheduler;
    let streamScheduler;
    let streamProcessor;
    let running = false;
    let shutdown = false;
    const wait = (ms) => {
        return new Promise((resolve) => {
            setTimeout(resolve, ms);
        });
    };
    const cronHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        if (manager.cronSchedulerHandler) {
            let lock;
            const startDate = utcDate();
            try {
                // date
                // Lock the manager
                lock = yield lockResource([manager.cronSchedulerHandler.lockKey], { retryCount: 0 });
                running = true;
                yield manager.cronSchedulerHandler.handler();
            }
            catch (e) {
                if (e.name === TYPE_LOCK_ERROR) {
                    logApp.debug(`[OPENCTI-MODULE] ${manager.label} already started by another API`);
                }
                else {
                    logApp.error(e, { manager: manager.id });
                }
            }
            finally {
                running = false;
                if (lock)
                    yield lock.unlock();
                if (startDate) {
                    const duration = moment.duration(utcDate().diff(startDate)).asMilliseconds();
                    logApp.debug(`[OPENCTI-MODULE] ${manager.label} done in ${duration}ms`);
                }
            }
        }
    });
    const streamHandler = () => __awaiter(void 0, void 0, void 0, function* () {
        if (manager.streamSchedulerHandler) {
            let lock;
            try {
                // Lock the manager
                lock = yield lockResource([manager.streamSchedulerHandler.lockKey], { retryCount: 0 });
                running = true;
                logApp.info(`[OPENCTI-MODULE] Running ${manager.label} stream handler`);
                streamProcessor = createStreamProcessor(SYSTEM_USER, 'File index manager', manager.streamSchedulerHandler.handler, manager.streamSchedulerHandler.streamOpts);
                const startFrom = manager.streamSchedulerHandler.streamProcessorStartFrom();
                yield streamProcessor.start(startFrom);
                while (!shutdown && streamProcessor.running()) {
                    lock.signal.throwIfAborted();
                    yield wait(WAIT_TIME_ACTION);
                }
                logApp.info(`[OPENCTI-MODULE] End of ${manager.label} stream handler`);
            }
            catch (e) {
                if (e.name === TYPE_LOCK_ERROR) {
                    logApp.debug(`[OPENCTI-MODULE] ${manager.label} stream handler already started by another API`);
                }
                else {
                    logApp.error(e, { manager: manager.id });
                }
            }
            finally {
                if (streamProcessor)
                    yield streamProcessor.shutdown();
                if (lock)
                    yield lock.unlock();
            }
        }
    });
    return {
        manager,
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info(`[OPENCTI-MODULE] Starting ${manager.label}`);
            if (manager.cronSchedulerHandler) {
                scheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                    yield cronHandler();
                }), manager.cronSchedulerHandler.interval);
            }
            if (manager.streamSchedulerHandler) {
                streamScheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                    yield streamHandler();
                }), manager.streamSchedulerHandler.interval);
            }
        }),
        status: (settings) => {
            var _a;
            return {
                id: manager.id,
                enable: manager.enabled(settings),
                running,
                warning: ((_a = manager.warning) === null || _a === void 0 ? void 0 : _a.call(manager)) || false,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info(`[OPENCTI-MODULE] Stopping ${manager.label}`);
            shutdown = true;
            if (scheduler)
                yield clearIntervalAsync(scheduler);
            if (streamScheduler)
                yield clearIntervalAsync(streamScheduler);
            return true;
        }),
    };
};
const managersModule = {
    managers: [],
    add(managerModule) {
        this.managers.push(managerModule);
    },
};
export const registerManager = (manager) => {
    const managerModule = initManager(manager);
    managersModule.add(managerModule);
};
export const startAllManagers = () => __awaiter(void 0, void 0, void 0, function* () {
    for (let i = 0; i < managersModule.managers.length; i += 1) {
        const managerModule = managersModule.managers[i];
        if (managerModule.manager.enabledToStart()) {
            yield managerModule.start();
        }
        else {
            logApp.info(`[OPENCTI-MODULE] ${managerModule.manager.label} not started (disabled by configuration)`);
        }
    }
});
export const getAllManagersStatuses = (settings) => {
    return [...managersModule.managers.map((module) => module.status(settings))];
};
