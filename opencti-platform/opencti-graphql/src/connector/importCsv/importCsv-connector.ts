import { Readable } from 'stream';
import * as readline from 'node:readline';
import type { SdkStream } from '@smithy/types/dist-types/serde';
import conf, { logApp } from '../../config/conf';
import { executionContext } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import { consumeQueue, registerConnectorQueues } from '../../database/rabbitmq';
import { downloadFile } from '../../database/raw-file-storage';
import { addDraftContext, reportExpectation, updateExpectationsNumber, updateProcessedTime, updateReceivedTime } from '../../domain/work';
import { bundleProcess, type CsvBundlerIngestionOpts, generateAndSendBundleProcess } from '../../parser/csv-bundler';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { resolveUserByIdFromCache } from '../../domain/user';
import { parseCsvMapper, sanitized, validateCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
import { IMPORT_CSV_CONNECTOR } from './importCsv';
import { FunctionalError } from '../../config/errors';
import { uploadToStorage } from '../../database/file-storage';
import { storeLoadByIdWithRefs } from '../../database/middleware';
import type { ConnectorConfig } from '../internalConnector';
import { addDraftWorkspace } from '../../modules/draftWorkspace/draftWorkspace-domain';

const RETRY_CONNECTION_PERIOD = 10000;
const BULK_LINE_PARSING_NUMBER = conf.get('import_csv_built_in_connector:bulk_creation_size') || 5000;
const connector = IMPORT_CSV_CONNECTOR;

const connectorConfig: ConnectorConfig = {
  id: 'IMPORT_CSV_BUILT_IN_CONNECTOR',
  name: 'Import Csv built in connector',
  config: {
    enable: conf.get('import_csv_built_in_connector:enabled'),
    validate_before_import: conf.get('import_csv_built_in_connector:validate_before_import')
  }
};
const LOG_PREFIX = `[OPENCTI-MODULE][${connectorConfig.id}]`;

/** @deprecated Will be removed when workbench are replaced by draft */
const processCSVforWorkbench = async (context: AuthContext, fileId: string, opts: CsvBundlerIngestionOpts) => {
  const { workId, applicantUser, csvMapper, entity } = opts;
  const stream: SdkStream<Readable> | null | undefined = await downloadFile(fileId) as SdkStream<Readable> | null | undefined;
  if (stream) {
    // Starting to work, importing file = 1 operation
    await updateExpectationsNumber(context, applicantUser, workId, 1);
    const chunks: string[] = [];
    let hasError: boolean = false;
    stream.on('data', async (chunk) => {
      chunks.push(chunk.toString('utf8'));
    }).on('error', async (error) => {
      hasError = true;
      const errorData = { error: error.message, source: fileId };
      await reportExpectation(context, applicantUser, workId, errorData);
      logApp.error(`${LOG_PREFIX} Error streaming the CSV data`, { cause: error });
    }).on('end', async () => {
      if (!hasError) {
        // it's fine to use deprecated bundleProcess since this whole method is also deprecated for drafts.
        const bundle = await bundleProcess(context, applicantUser, chunks, csvMapper, { entity });

        const contentStream = Readable.from([JSON.stringify(bundle, null, '  ')]);
        const file = {
          createReadStream: () => contentStream,
          filename: `${opts.workId}.json`,
          mimetype: 'application/json',
        };
        await uploadToStorage(context, applicantUser, 'import/pending', file, { entity });
        await reportExpectation(context, applicantUser, workId);
      }
    });
  }
  await updateProcessedTime(context, applicantUser, workId, '1 generated bundle for workbench validation.');
};

export const processCSVforWorkers = async (context: AuthContext, fileId: string, opts: CsvBundlerIngestionOpts) => {
  logApp.info(`${LOG_PREFIX} processing CSV ${fileId} START.`);
  const { workId, applicantUser } = opts;

  await validateCsvMapper(context, applicantUser, opts.csvMapper);
  const sanitizedMapper = sanitized(opts.csvMapper);
  let removeHeaderIsRequired = sanitizedMapper.has_header;
  let bulkLineCursor = 0;
  let hasMoreBulk = true;
  let totalObjectsCount = 0;
  let totalBundlesCount = 0;

  const startDate2 = new Date().getTime();
  while (hasMoreBulk) {
    // The file cannot stay open too long, so until we reach end of file (hasMoreBulk==true) we:
    // - read the file
    // - takes the bulk count lines
    // - ** close file
    // - process the bulk count lines.

    const stream: SdkStream<Readable> | null | undefined = await downloadFile(fileId) as SdkStream<Readable> | null | undefined;
    if (stream) {
      const lines: string[] = [];
      const readStream = readline.createInterface({ input: stream, crlfDelay: Infinity });
      let lineNumber = 0;
      try {
        const startDate = new Date().getTime();
        const startingLineNumber = bulkLineCursor;
        logApp.info(`${LOG_PREFIX} reading line from ${bulkLineCursor} to ${BULK_LINE_PARSING_NUMBER + bulkLineCursor}`);
        // Need an async interator to prevent blocking
        // eslint-disable-next-line no-restricted-syntax
        for await (const line of readStream) {
          if (startingLineNumber <= lineNumber && lineNumber < startingLineNumber + BULK_LINE_PARSING_NUMBER) {
            // We are in the bulk window
            if (removeHeaderIsRequired) {
              // Manage header removal: if csv file start with skip char, need to skipline until header is there
              if (sanitizedMapper.skipLineChar && sanitizedMapper.skipLineChar.length === 1) {
                if (!line.startsWith(sanitizedMapper.skipLineChar)) {
                  removeHeaderIsRequired = false;
                }
              } else {
                removeHeaderIsRequired = false;
              }
            } else {
              lines.push(line);
            }
            bulkLineCursor += 1;
          }
          lineNumber += 1;
        }
        readStream.close();

        hasMoreBulk = bulkLineCursor < lineNumber;
        logApp.info(`${LOG_PREFIX} read lines end on ${new Date().getTime() - startDate} ms; hasMoreBulk=${hasMoreBulk}; lineNumber=${lineNumber}`);

        if (lines.length > 0) {
          try {
            logApp.info(`${LOG_PREFIX} generating bundle with ${lines.length} csv lines`);
            const { bundleCount, objectCount } = await generateAndSendBundleProcess(context, lines, opts);
            totalObjectsCount += objectCount;
            totalBundlesCount += bundleCount;
          } catch (error: any) {
            const errorData = { error: error.message, source: `${fileId}, from ${lineNumber} and ${BULK_LINE_PARSING_NUMBER} following lines.` };
            logApp.error(`${LOG_PREFIX} CSV line parsing error`, { cause: errorData });
            await reportExpectation(context, applicantUser, workId, errorData);
          }
        }
      } catch (error: any) {
        logApp.error(`${LOG_PREFIX} CSV global parsing error`, { cause: error });
        const errorData = { error: error.message, source: fileId };
        await reportExpectation(context, applicantUser, workId, errorData);
        // circuit breaker
        hasMoreBulk = false;
      } finally {
        readStream.close();
      }
    } else {
      // stream null means error, to change the day downloadFile throw errors.
      // To change when downloadFile is changed to throw exception.
      // circuit breaker
      hasMoreBulk = false;
      logApp.error(`${LOG_PREFIX} Cannot download file, please check the file storage dependency.`, { fileId, workId });
      const errorData = { error: 'Cannot download file', source: fileId };
      await reportExpectation(context, applicantUser, workId, errorData);
    }
  }
  logApp.info(`${LOG_PREFIX} processing CSV ${fileId} DONE in ${new Date().getTime() - startDate2} ms for ${totalObjectsCount} objets in ${totalBundlesCount} bundles.`);

  // expectation number is going to be increase when worker split bundle. So it's bundle count that should be reported in updateProcessedTime.
  if (totalBundlesCount > 0) {
    await updateProcessedTime(context, applicantUser, workId, `${totalBundlesCount} bundle(s) send to worker for import.`);

    // csv file ends = 1 operation done.
    // to keep after updateProcessedTime or else work is deleted.
    await reportExpectation(context, applicantUser, workId);
  } else {
    await updateProcessedTime(context, applicantUser, workId, 'No bundle send to worker for import.');
    await reportExpectation(context, applicantUser, workId);// csv file ends = 1 operation done.
  }

  return { totalObjectsCount, totalBundlesCount };
};

const processValidateBeforeImport = async (context: AuthContext, validationMode: string, draftId: string, fileId: string, opts: CsvBundlerIngestionOpts) => {
  if (draftId) {
    const contextInDraft = { ...context, draft_context: draftId };
    await processCSVforWorkers(contextInDraft, fileId, { ...opts, draftId });
  } else if (validationMode === 'draft') {
    const { id } = await addDraftWorkspace(context, opts.applicantUser, { name: fileId, entity_id: opts.entity?.id ?? '' });
    await addDraftContext(context, opts.applicantUser, opts.workId, id);
    const contextInDraft = { ...context, draft_context: id };
    await processCSVforWorkers(contextInDraft, fileId, { ...opts, draftId: id });
  } else {
    await processCSVforWorkbench(context, fileId, opts);
  }
};

const consumeQueueCallback = async (context: AuthContext, message: string) => {
  const messageParsed = JSON.parse(message);
  const workId = messageParsed.internal.work_id;
  const applicantId = messageParsed.internal.applicant_id ?? OPENCTI_SYSTEM_UUID;
  const fileId = messageParsed.event.file_id;
  logApp.info(`${LOG_PREFIX} Starting to process CSV file.`, { fileId, workId, applicantId });
  const applicantUser = await resolveUserByIdFromCache(context, applicantId) as AuthUser;
  const entityId = messageParsed.event.entity_id;
  const entity = entityId ? await storeLoadByIdWithRefs(context, applicantUser, entityId) : undefined;
  let parsedConfiguration;
  try {
    parsedConfiguration = JSON.parse(messageParsed.configuration);
  } catch (error) {
    throw FunctionalError('Could not parse CSV mapper configuration', { error });
  }
  try {
    const csvMapper = parseCsvMapper(parsedConfiguration);
    const opts: CsvBundlerIngestionOpts = {
      workId,
      applicantUser,
      csvMapper,
      entity,
      connectorId: connector.internal_id,
    };
    await updateReceivedTime(context, applicantUser, workId, 'Connector ready to process the operation');
    const { validation_mode, force_validation } = messageParsed.event;
    const { draft_id } = messageParsed.internal;
    const validateBeforeImport = connectorConfig.config.validate_before_import;
    if (draft_id || validateBeforeImport || force_validation) {
      await processValidateBeforeImport(context, validation_mode, draft_id, fileId, opts);
    } else {
      await processCSVforWorkers(context, fileId, opts);
    }
  } catch (error: any) {
    logApp.error(`${LOG_PREFIX} CSV global parsing error`, { cause: error, source: fileId });
    const errorData = { error: error.stack, source: fileId };
    await reportExpectation(context, applicantUser, workId, errorData);
  }
};

export const initImportCsvConnector = () => {
  const { config } = connectorConfig;

  let rabbitMqConnection: { close: () => void };

  const connectionSetterCallback = (conn: any) => {
    rabbitMqConnection = conn;
  };

  const handleCsvImport = async (context: AuthContext) => {
    consumeQueue(context, connector.id, connectionSetterCallback, consumeQueueCallback).catch(() => {
      if (rabbitMqConnection) {
        try {
          rabbitMqConnection.close();
        } catch (e) {
          logApp.error(`${LOG_PREFIX} Closing RabbitMQ connection failed`, { cause: e });
        }
      }
      // TODO REMOVE TYPING, don't know why it's not working
      setTimeout(handleCsvImport as unknown as (args: void) => void, RETRY_CONNECTION_PERIOD);
    });
  };

  return {
    start: async () => {
      const context = executionContext(connectorConfig.id.toLowerCase());
      logApp.info(`${LOG_PREFIX} Starting ${connectorConfig.name} manager`);
      await registerConnectorQueues(connector.id, connector.name, connector.connector_type, connector.connector_scope);
      await handleCsvImport(context);
    },
    status: () => {
      return {
        id: connectorConfig.id,
        enable: config.enable ?? false,
        running: config.enable ?? false,
      };
    },
    shutdown: async () => {
      logApp.info(`${LOG_PREFIX} Stopping ${connectorConfig.name} manager`);
      if (rabbitMqConnection) rabbitMqConnection.close();
      return true;
    },
  };
};

const importCsvConnector = initImportCsvConnector();

export default importCsvConnector;
