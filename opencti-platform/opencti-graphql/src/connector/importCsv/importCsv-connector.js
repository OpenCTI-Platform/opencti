var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Readable } from 'stream';
import conf, { logApp } from '../../config/conf';
import { executionContext } from '../../utils/access';
import { consumeQueue, pushToSync, registerConnectorQueues } from '../../database/rabbitmq';
import { downloadFile, upload } from '../../database/file-storage';
import { reportExpectation, updateExpectationsNumber, updateProcessedTime, updateReceivedTime } from '../../domain/work';
import { bundleProcess } from '../../parser/csv-bundler';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { resolveUserById } from '../../domain/user';
import { parseCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
import { IMPORT_CSV_CONNECTOR } from './importCsv';
import { internalLoadById } from '../../database/middleware-loader';
const RETRY_CONNECTION_PERIOD = 10000;
const connectorConfig = {
    id: 'IMPORT_CSV_BUILT_IN_CONNECTOR',
    name: 'Import Csv built in connector',
    config: {
        enable: conf.get('import_csv_built_in_connector:enabled'),
        validate_before_import: conf.get('import_csv_built_in_connector:validate_before_import')
    }
};
const initImportCsvConnector = () => {
    const { config } = connectorConfig;
    const connector = IMPORT_CSV_CONNECTOR;
    let rabbitMqConnection;
    const connectionSetterCallback = (conn) => {
        rabbitMqConnection = conn;
    };
    const consumeQueueCallback = (context, message) => __awaiter(void 0, void 0, void 0, function* () {
        const messageParsed = JSON.parse(message);
        const workId = messageParsed.internal.work_id;
        const applicantId = messageParsed.internal.applicant_id;
        const fileId = messageParsed.event.file_id;
        const applicantUser = yield resolveUserById(context, applicantId);
        const entityId = messageParsed.event.entity_id;
        const entity = entityId ? yield internalLoadById(context, applicantUser, entityId) : undefined;
        try {
            const csvMapper = parseCsvMapper(JSON.parse(messageParsed.configuration));
            const stream = yield downloadFile(fileId);
            yield updateReceivedTime(context, applicantUser, workId, 'Connector ready to process the operation');
            if (stream) {
                const chunks = [];
                let hasError = false;
                stream.on('data', (chunk) => __awaiter(void 0, void 0, void 0, function* () {
                    chunks.push(chunk.toString('utf8'));
                })).on('error', (error) => __awaiter(void 0, void 0, void 0, function* () {
                    hasError = true;
                    const errorData = {
                        error: error.message,
                        source: fileId,
                    };
                    yield reportExpectation(context, applicantUser, workId, errorData);
                }))
                    .on('end', () => __awaiter(void 0, void 0, void 0, function* () {
                    if (!hasError) {
                        const string = chunks.join('');
                        const bundle = yield bundleProcess(context, applicantUser, Buffer.from(string), csvMapper, entity);
                        yield updateExpectationsNumber(context, applicantUser, workId, 1);
                        const validateBeforeImport = connectorConfig.config.validate_before_import;
                        if (validateBeforeImport) {
                            const contentStream = Readable.from([JSON.stringify(bundle, null, '  ')]);
                            const file = {
                                createReadStream: () => contentStream,
                                filename: `${workId}.json`,
                                mimetype: 'application/json',
                            };
                            yield upload(context, applicantUser, 'import/pending', file, { entity });
                            yield reportExpectation(context, applicantUser, workId);
                        }
                        else {
                            const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
                            yield pushToSync({
                                type: 'bundle',
                                update: true,
                                applicant_id: applicantId !== null && applicantId !== void 0 ? applicantId : OPENCTI_SYSTEM_UUID,
                                work_id: workId,
                                content
                            });
                        }
                    }
                }));
            }
            yield updateProcessedTime(context, applicantUser, workId, ' generated bundle(s) for worker import');
        }
        catch (error) {
            const errorData = {
                error: error.stack,
                source: fileId,
            };
            yield reportExpectation(context, applicantUser, workId, errorData);
        }
    });
    const handleCsvImport = (context) => __awaiter(void 0, void 0, void 0, function* () {
        consumeQueue(context, connector.id, connectionSetterCallback, consumeQueueCallback).catch(() => {
            if (rabbitMqConnection)
                rabbitMqConnection.close();
            setTimeout(handleCsvImport, RETRY_CONNECTION_PERIOD);
        });
    });
    return {
        start: () => __awaiter(void 0, void 0, void 0, function* () {
            const context = executionContext(connectorConfig.id.toLowerCase());
            logApp.info(`[OPENCTI-MODULE] Starting ${connectorConfig.name} manager`);
            yield registerConnectorQueues(connector.id, connector.name, connector.connector_type, connector.connector_scope);
            yield handleCsvImport(context);
        }),
        status: () => {
            var _a, _b;
            return {
                id: connectorConfig.id,
                enable: (_a = config.enable) !== null && _a !== void 0 ? _a : false,
                running: (_b = config.enable) !== null && _b !== void 0 ? _b : false,
            };
        },
        shutdown: () => __awaiter(void 0, void 0, void 0, function* () {
            logApp.info(`[OPENCTI-MODULE] Stopping ${connectorConfig.name} manager`);
            if (rabbitMqConnection)
                rabbitMqConnection.close();
            return true;
        }),
    };
};
const importCsvConnector = initImportCsvConnector();
export default importCsvConnector;
