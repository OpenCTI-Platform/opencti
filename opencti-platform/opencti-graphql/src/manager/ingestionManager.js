var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { parseStringPromise as xmlParse } from 'xml2js';
import TurndownService from 'turndown';
import bcrypt from 'bcryptjs';
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/dynamic';
import { AxiosHeaders } from 'axios';
import { lockResource } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnknownError, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { getHttpClient } from '../utils/http-client';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { FROM_START_STR, sanitizeForMomentParsing, utcDate } from '../utils/format';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { pushToSync } from '../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { findAllRssIngestions, patchRssIngestion } from '../modules/ingestion/ingestion-rss-domain';
import { findAllTaxiiIngestions, patchTaxiiIngestion } from '../modules/ingestion/ingestion-taxii-domain';
import { TaxiiVersion } from '../generated/graphql';
import { fetchCsvFromUrl, findAllCsvIngestions, patchCsvIngestion, testCsvIngestionMapping } from '../modules/ingestion/ingestion-csv-domain';
import { findById } from '../modules/internal/csvMapper/csvMapper-domain';
import { bundleProcess } from '../parser/csv-bundler';
import { createWork, updateExpectationsNumber } from '../domain/work';
import { IMPORT_CSV_CONNECTOR } from '../connector/importCsv/importCsv';
// Ingestion manager responsible to cleanup old data
// Each API will start is ingestion manager.
// If the lock is free, every API as the right to take it.
const SCHEDULE_TIME = conf.get('ingestion_manager:interval') || 300000;
const INGESTION_MANAGER_KEY = conf.get('ingestion_manager:lock_key') || 'ingestion_manager_lock';
let running = false;
// region utils
const asArray = (data) => {
    if (data) {
        if (Array.isArray(data)) {
            return data;
        }
        return [data];
    }
    return [];
};
const rssItemV1Convert = (turndownService, feed, entry) => {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    const { updated } = feed;
    return {
        title: turndownService.turndown(entry.title._),
        description: turndownService.turndown((_b = (_a = entry.summary) === null || _a === void 0 ? void 0 : _a._) !== null && _b !== void 0 ? _b : ''),
        link: isNotEmptyField(entry.link) ? (_c = entry.link.href) === null || _c === void 0 ? void 0 : _c.trim() : '',
        content: turndownService.turndown((_e = (_d = entry.content) === null || _d === void 0 ? void 0 : _d._) !== null && _e !== void 0 ? _e : ''),
        labels: [], // No label in rss v1
        pubDate: utcDate(sanitizeForMomentParsing((_h = (_g = (_f = entry.updated) === null || _f === void 0 ? void 0 : _f._) !== null && _g !== void 0 ? _g : updated === null || updated === void 0 ? void 0 : updated._) !== null && _h !== void 0 ? _h : FROM_START_STR)),
    };
};
const rssItemV2Convert = (turndownService, channel, item) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
    const { pubDate } = channel;
    return {
        title: turndownService.turndown((_a = item.title._) !== null && _a !== void 0 ? _a : ''),
        description: turndownService.turndown((_c = (_b = item.description) === null || _b === void 0 ? void 0 : _b._) !== null && _c !== void 0 ? _c : ''),
        link: isNotEmptyField(item.link) ? ((_d = item.link._) !== null && _d !== void 0 ? _d : '').trim() : '',
        content: turndownService.turndown((_h = (_f = (_e = item['content:encoded']) === null || _e === void 0 ? void 0 : _e._) !== null && _f !== void 0 ? _f : (_g = item.content) === null || _g === void 0 ? void 0 : _g._) !== null && _h !== void 0 ? _h : ''),
        labels: R.uniq(asArray(item.category).filter((c) => isNotEmptyField(c)).map((c) => c._.trim())),
        pubDate: utcDate(sanitizeForMomentParsing((_l = (_k = (_j = item.pubDate) === null || _j === void 0 ? void 0 : _j._) !== null && _k !== void 0 ? _k : pubDate === null || pubDate === void 0 ? void 0 : pubDate._) !== null && _l !== void 0 ? _l : FROM_START_STR)),
    };
};
const rssHttpGetter = () => {
    const httpClient = getHttpClient({
        responseType: 'text',
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0' }
    });
    return (uri) => __awaiter(void 0, void 0, void 0, function* () {
        const { data } = yield httpClient.get(uri);
        return data;
    });
};
// RSS Title is mandatory
// A valid date is required, and after the current_state_date
const rssDataFilter = (items, current_state_date) => {
    return items.filter((e) => isNotEmptyField(e.title))
        .filter((e) => e.pubDate.isValid())
        .filter((e) => isEmptyField(current_state_date) || e.pubDate.isAfter(current_state_date))
        .sort((a, b) => a.pubDate.diff(b.pubDate));
};
export const rssDataParser = (turndownService, data, current_state_date) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    const xmlData = yield xmlParse(data, { explicitArray: false, trim: true, explicitCharkey: true, mergeAttrs: true });
    if (xmlData === null || xmlData === void 0 ? void 0 : xmlData.feed) { // Atom V1
        const entries = asArray(xmlData.feed.entry);
        const rssItems = entries.map((entry) => rssItemV1Convert(turndownService, xmlData.feed, entry));
        return rssDataFilter(rssItems, current_state_date);
    }
    if (xmlData === null || xmlData === void 0 ? void 0 : xmlData.rss) { // Atom V2
        const channels = asArray((_a = xmlData === null || xmlData === void 0 ? void 0 : xmlData.rss) === null || _a === void 0 ? void 0 : _a.channel);
        const rssItems = channels.map((channel) => asArray(channel.item).map((item) => rssItemV2Convert(turndownService, channel, item))).flat();
        return rssDataFilter(rssItems, current_state_date);
    }
    return [];
});
const rssDataHandler = (context, httpRssGet, turndownService, ingestion) => __awaiter(void 0, void 0, void 0, function* () {
    var _b, _c;
    const data = yield httpRssGet(ingestion.uri);
    const items = yield rssDataParser(turndownService, data, ingestion.current_state_date);
    // Build Stix bundle from items
    if (items.length > 0) {
        logApp.info(`[OPENCTI-MODULE] Rss ingestion execution for ${items.length} items`);
        const reports = items.map((item) => {
            const report = {
                type: 'report',
                name: item.title,
                labels: item.labels,
                description: item.description,
                created_by_ref: ingestion.created_by_ref,
                object_marking_refs: ingestion.object_marking_refs,
                report_types: ingestion.report_types,
                published: item.pubDate.toISOString(),
            };
            report.id = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, report);
            if (item.link) {
                report.external_references = [{
                        source_name: item.title,
                        description: `${ingestion.name} ${item.title}. Retrieved ${item.pubDate.toISOString()}.`,
                        url: item.link
                    }];
            }
            return report;
        });
        const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: reports };
        // Push the bundle to absorption queue
        const stixBundle = JSON.stringify(bundle);
        const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
        yield pushToSync({ type: 'bundle', applicant_id: (_b = ingestion.user_id) !== null && _b !== void 0 ? _b : OPENCTI_SYSTEM_UUID, content, update: true });
        // Update the state
        const lastPubDate = (_c = R.last(items)) === null || _c === void 0 ? void 0 : _c.pubDate;
        yield patchRssIngestion(context, SYSTEM_USER, ingestion.internal_id, { current_state_date: lastPubDate });
    }
});
const rssExecutor = (context, turndownService) => __awaiter(void 0, void 0, void 0, function* () {
    const httpGet = rssHttpGetter();
    const filters = {
        mode: 'and',
        filters: [{ key: 'ingestion_running', values: [true] }],
        filterGroups: [],
    };
    const opts = { filters, connectionFormat: false, noFiltersChecking: true };
    const ingestions = yield findAllRssIngestions(context, SYSTEM_USER, opts);
    const ingestionPromises = [];
    for (let i = 0; i < ingestions.length; i += 1) {
        const ingestion = ingestions[i];
        const ingestionPromise = rssDataHandler(context, httpGet, turndownService, ingestion)
            .catch((e) => {
            logApp.error(e, { name: ingestion.name, context: 'Rss execution' });
        });
        ingestionPromises.push(ingestionPromise);
    }
    return Promise.all(ingestionPromises);
});
const taxiiHttpGet = (ingestion) => __awaiter(void 0, void 0, void 0, function* () {
    const headers = new AxiosHeaders();
    headers.Accept = 'application/taxii+json;version=2.1';
    if (ingestion.authentication_type === 'basic') {
        const auth = Buffer.from(ingestion.authentication_value, 'utf-8').toString('base64');
        headers.Authorization = `Basic ${auth}`;
    }
    if (ingestion.authentication_type === 'bearer') {
        headers.Authorization = `Bearer ${ingestion.authentication_value}`;
    }
    let certificates;
    if (ingestion.authentication_type === 'certificate') {
        certificates = { cert: ingestion.authentication_value.split(':')[0], key: ingestion.authentication_value.split(':')[1], ca: ingestion.authentication_value.split(':')[0] };
    }
    const httpClientOptions = { headers, rejectUnauthorized: false, responseType: 'json', certificates };
    const httpClient = getHttpClient(httpClientOptions);
    const preparedUri = ingestion.uri.endsWith('/') ? ingestion.uri : `${ingestion.uri}/`;
    const url = `${preparedUri}collections/${ingestion.collection}/objects/`;
    // https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html#_Toc31107519
    // If the more property is set to true and the next property is populated then the client can paginate through the remaining records using the next URL parameter along with the
    // same original query options.
    // If the more property is set to true and the next property is empty then the client may paginate through the remaining records by using the added_after URL parameter with the
    // date/time value from the X-TAXII-Date-Added-Last header along with the same original query options.
    const next = ingestion.current_state_cursor;
    const params = { next, added_after: ingestion.added_after_start };
    const { data, headers: resultHeaders } = yield httpClient.get(url, { params });
    return { data, addedLast: resultHeaders['x-taxii-date-added-last'] };
});
const taxiiV21DataHandler = (context, ingestion) => __awaiter(void 0, void 0, void 0, function* () {
    var _d;
    const { data, addedLast } = yield taxiiHttpGet(ingestion);
    if (data.objects && data.objects.length > 0) {
        logApp.info(`[OPENCTI-MODULE] Taxii ingestion execution for ${data.objects.length} items`);
        const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: data.objects };
        // Push the bundle to absorption queue
        const stixBundle = JSON.stringify(bundle);
        const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
        yield pushToSync({ type: 'bundle', applicant_id: (_d = ingestion.user_id) !== null && _d !== void 0 ? _d : OPENCTI_SYSTEM_UUID, content, update: true });
        // Update the state
        yield patchTaxiiIngestion(context, SYSTEM_USER, ingestion.internal_id, {
            current_state_cursor: data.next ? String(data.next) : undefined,
            added_after_start: data.next ? ingestion.added_after_start : utcDate(addedLast)
        });
    }
    else if (data.objects === undefined) {
        const error = UnknownError('Undefined taxii objects', data);
        logApp.error(error, { name: ingestion.name, context: 'Taxii 2.1 transform' });
    }
});
const TAXII_HANDLERS = {
    [TaxiiVersion.V21]: taxiiV21DataHandler
};
const taxiiExecutor = (context) => __awaiter(void 0, void 0, void 0, function* () {
    const filters = {
        mode: 'and',
        filters: [{ key: 'ingestion_running', values: [true] }],
        filterGroups: [],
    };
    const opts = { filters, connectionFormat: false, noFiltersChecking: true };
    const ingestions = yield findAllTaxiiIngestions(context, SYSTEM_USER, opts);
    const ingestionPromises = [];
    for (let i = 0; i < ingestions.length; i += 1) {
        const ingestion = ingestions[i];
        const taxiiHandler = TAXII_HANDLERS[ingestion.version];
        if (!taxiiHandler) {
            throw UnsupportedError(`[OPENCTI-MODULE] Taxii version ${ingestion.version} is not yet supported`);
        }
        const ingestionPromise = taxiiHandler(context, ingestion)
            .catch((e) => {
            logApp.error(e, { name: ingestion.name, context: 'Taxii ingestion execution' });
        });
        ingestionPromises.push(ingestionPromise);
    }
    return Promise.all(ingestionPromises);
});
const csvHttpGet = (ingestion) => __awaiter(void 0, void 0, void 0, function* () {
    const headers = new AxiosHeaders();
    headers.Accept = 'application/csv';
    if (ingestion.authentication_type === 'basic') {
        const auth = Buffer.from(ingestion.authentication_value, 'utf-8').toString('base64');
        headers.Authorization = `Basic ${auth}`;
    }
    if (ingestion.authentication_type === 'bearer') {
        headers.Authorization = `Bearer ${ingestion.authentication_value}`;
    }
    let certificates;
    if (ingestion.authentication_type === 'certificate') {
        const [cert, key, ca] = ingestion.authentication_value.split(':');
        certificates = { cert, key, ca };
    }
    const httpClientOptions = { headers, rejectUnauthorized: false, responseType: 'json', certificates };
    const httpClient = getHttpClient(httpClientOptions);
    const { data, headers: resultHeaders } = yield httpClient.get(ingestion.uri);
    return { data, addedLast: resultHeaders['x-csv-date-added-last'] };
});
const csvDataToObjects = (data, ingestion, csvMapper, context) => __awaiter(void 0, void 0, void 0, function* () {
    var _e;
    const entitiesData = data.split('\n');
    const csvBuffer = yield fetchCsvFromUrl(ingestion.uri, csvMapper.skipLineChar);
    const { objects } = yield bundleProcess(context, (_e = context.user) !== null && _e !== void 0 ? _e : SYSTEM_USER, csvBuffer, csvMapper);
    if (objects === undefined) {
        const error = UnknownError('Undefined CSV objects', data);
        logApp.error(error, { name: ingestion.name, context: 'CSV transform' });
    }
    logApp.info(`[OPENCTI-MODULE] CSV ingestion execution for ${entitiesData.length} items`);
    return objects;
});
const csvDataHandler = (context, ingestion) => __awaiter(void 0, void 0, void 0, function* () {
    var _f, _g, _h;
    const { data, addedLast } = yield csvHttpGet(ingestion);
    const user = (_f = context.user) !== null && _f !== void 0 ? _f : SYSTEM_USER;
    const csvMapper = yield findById(context, user, ingestion.csv_mapper_id);
    const csvMappingTestResult = yield testCsvIngestionMapping(context, user, ingestion.uri, ingestion.csv_mapper_id);
    if (!csvMappingTestResult.nbEntities) {
        const error = UnknownError('Invalid data from URL', data);
        logApp.error(error, { name: ingestion.name, context: 'CSV transform' });
    }
    const isUnchangedData = bcrypt.compareSync(data, (_g = ingestion.current_state_hash) !== null && _g !== void 0 ? _g : '');
    if (isUnchangedData) {
        return;
    }
    const objects = yield csvDataToObjects(data, ingestion, csvMapper, context);
    const bundleSize = 1000;
    for (let index = 0; index < objects.length; index += bundleSize) {
        // Filter objects already added to queue
        const splitBundle = objects.slice(index, index + bundleSize);
        const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: splitBundle };
        const stixBundle = JSON.stringify(bundle);
        const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
        const friendlyName = 'CSV feed Ingestion';
        const work = yield createWork(context, user, IMPORT_CSV_CONNECTOR, friendlyName, IMPORT_CSV_CONNECTOR.id);
        yield updateExpectationsNumber(context, user, work.id, 1);
        yield pushToSync({ type: 'bundle', applicant_id: (_h = ingestion.user_id) !== null && _h !== void 0 ? _h : OPENCTI_SYSTEM_UUID, work_id: work.id, content, update: true });
    }
    // Update the state
    const hashedIncomingData = bcrypt.hashSync(data);
    yield patchCsvIngestion(context, SYSTEM_USER, ingestion.internal_id, {
        current_state_hash: hashedIncomingData,
        added_after_start: utcDate(addedLast)
    });
});
const csvExecutor = (context) => __awaiter(void 0, void 0, void 0, function* () {
    const filters = {
        mode: 'and',
        filters: [{ key: 'ingestion_running', values: [true] }],
        filterGroups: [],
    };
    const opts = { filters, connectionFormat: false, noFiltersChecking: true };
    const ingestions = yield findAllCsvIngestions(context, SYSTEM_USER, opts);
    const ingestionPromises = [];
    for (let i = 0; i < ingestions.length; i += 1) {
        const ingestion = ingestions[i];
        const ingestionPromise = csvDataHandler(context, ingestion)
            .catch((e) => {
            logApp.error(`[OPENCTI-MODULE] execution error for ${ingestion.name} : ${e}`, { error: e });
        });
        ingestionPromises.push(ingestionPromise);
    }
    return Promise.all(ingestionPromises);
});
// endregion
const ingestionHandler = () => __awaiter(void 0, void 0, void 0, function* () {
    logApp.debug('[OPENCTI-MODULE] Running ingestion manager');
    let lock;
    try {
        // Lock the manager
        const turndownService = new TurndownService();
        lock = yield lockResource([INGESTION_MANAGER_KEY], { retryCount: 0 });
        running = true;
        // noinspection JSUnusedLocalSymbols
        const context = executionContext('ingestion_manager');
        const ingestionPromises = [];
        ingestionPromises.push(rssExecutor(context, turndownService));
        ingestionPromises.push(taxiiExecutor(context));
        ingestionPromises.push(csvExecutor(context));
        yield Promise.all(ingestionPromises);
    }
    catch (e) {
        // We dont care about failing to get the lock.
        if (e.name === TYPE_LOCK_ERROR) {
            logApp.debug('[OPENCTI-MODULE] Ingestion manager already in progress by another API');
        }
        else {
            logApp.error(e, { manager: 'INGESTION_MANAGER' });
        }
    }
    finally {
        running = false;
        if (lock)
            yield lock.unlock();
    }
});
const initIngestionManager = () => {
    let scheduler;
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Running ingestion manager');
            scheduler = setIntervalAsync(() => __awaiter(void 0, void 0, void 0, function* () {
                yield ingestionHandler();
            }), SCHEDULE_TIME);
        }),
        status: () => {
            return {
                id: 'INGESTION_MANAGER',
                enable: booleanConf('ingestion_manager:enabled', false),
                running,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info('[OPENCTI-MODULE] Stopping ingestion manager');
            if (scheduler) {
                return clearIntervalAsync(scheduler);
            }
            return true;
        }),
    };
};
const ingestionManager = initIngestionManager();
export default ingestionManager;
