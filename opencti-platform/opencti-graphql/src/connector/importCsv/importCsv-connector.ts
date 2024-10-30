import { Readable } from 'stream';
import * as readline from 'node:readline';
import type { SdkStream } from '@smithy/types/dist-types/serde';
import conf, { logApp } from '../../config/conf';
import { executionContext } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import { consumeQueue, pushToWorkerForConnector, registerConnectorQueues } from '../../database/rabbitmq';
import { downloadFile } from '../../database/file-storage';
import { reportExpectation, updateExpectationsNumber, updateProcessedTime, updateReceivedTime } from '../../domain/work';
import { bundleProcess, bundleAllowUpsertProcess } from '../../parser/csv-bundler';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { resolveUserByIdFromCache } from '../../domain/user';
import { parseCsvMapper, sanitized, validateCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
import { IMPORT_CSV_CONNECTOR } from './importCsv';
import { DatabaseError, FunctionalError } from '../../config/errors';
import { uploadToStorage } from '../../database/file-storage-helper';
import { storeLoadByIdWithRefs } from '../../database/middleware';
import type { ConnectorConfig } from '../internalConnector';
import type { CsvMapperParsed } from '../../modules/internal/csvMapper/csvMapper-types';
import type { BasicStoreBase } from '../../types/store';
import { BundleBuilder } from '../../parser/bundle-creator';

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
const logPrefix = `[OPENCTI-MODULE] ${connectorConfig.name} `;

interface ConsumerOpts {
  workId: string,
  applicantUser: AuthUser,
  applicantId: string,
  entity: BasicStoreBase | undefined,
  csvMapper: CsvMapperParsed,
  fileId: string,
}

/**
 * Generate stix bundle and then push them all to the queue (for workers).
 * @param context
 * @param csvLines
 * @param opts
 */
const generateBundlesAndSendToWorkers = async (context: AuthContext, csvLines: string[], opts: ConsumerOpts) => {
  let bundleCount = 0;
  const { workId, applicantUser, applicantId, csvMapper, entity } = opts;
  const bundlesBuilder: BundleBuilder[] = await bundleAllowUpsertProcess(context, applicantUser, csvLines, csvMapper, { entity });
  logApp.debug(`${logPrefix} preparing ${bundlesBuilder.length} bundles`);
  for (let i = 0; i < bundlesBuilder.length; i += 1) {
    const bundle = bundlesBuilder[i].build();
    const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
    if (bundle.objects.length > 0) {
      logApp.debug(`${logPrefix} push bundle with ${bundle.objects.length} objects`);
      bundleCount += bundle.objects.length;
      await pushToWorkerForConnector(connector.internal_id, {
        type: 'bundle',
        update: true,
        applicant_id: applicantId ?? OPENCTI_SYSTEM_UUID,
        work_id: workId,
        content
      });
    }
  }
  return bundleCount;
};

/** @deprecated Will be removed when workbench are replaced by draft */
const processCSVforWorkbench = async (context: AuthContext, opts: ConsumerOpts) => {
  const { workId, fileId, applicantUser, csvMapper, entity } = opts;
  const stream: SdkStream<Readable> | null | undefined = await downloadFile(opts.fileId) as SdkStream<Readable> | null | undefined;
  if (stream) {
    const chunks: string[] = [];
    let hasError: boolean = false;
    stream.on('data', async (chunk) => {
      chunks.push(chunk.toString('utf8'));
    }).on('error', async (error) => {
      hasError = true;
      const errorData = { error: error.message, source: fileId };
      await reportExpectation(context, applicantUser, workId, errorData);
      logApp.error(error);
    }).on('end', async () => {
      if (!hasError) {
        // it's fine to use deprecated bundleProcess since this whole method is also deprecated for drafts.
        const bundle = await bundleProcess(context, applicantUser, chunks, csvMapper, { entity });

        await updateExpectationsNumber(context, applicantUser, workId, 1);
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

const processCSVforWorkers = async (context: AuthContext, opts: ConsumerOpts) => {
  const { workId, fileId, applicantUser } = opts;

  await validateCsvMapper(context, applicantUser, opts.csvMapper);
  const sanitizedMapper = sanitized(opts.csvMapper);

  let bulkLineCursor = 0;
  if (sanitizedMapper.has_header) {
    bulkLineCursor = 1;
  }

  let hasMoreBulk = true;
  let totalBundleCount = 0;
  const startDate2 = new Date().getTime();
  while (hasMoreBulk) {
    const stream: SdkStream<Readable> | null | undefined = await downloadFile(opts.fileId) as SdkStream<Readable> | null | undefined;
    if (stream) {
      const lines: string[] = [];
      const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
      let lineNumber = 0;
      try {
        const startDate = new Date().getTime();
        const startingLineNumber = bulkLineCursor;
        logApp.debug(`${logPrefix} reading line from ${bulkLineCursor} to ${BULK_LINE_PARSING_NUMBER + bulkLineCursor}`);
        // Need an async interator to prevent blocking
        // eslint-disable-next-line no-restricted-syntax
        for await (const line of rl) {
          if (startingLineNumber <= lineNumber && lineNumber < startingLineNumber + BULK_LINE_PARSING_NUMBER) {
            lines.push(line);
            bulkLineCursor += 1;
          }
          lineNumber += 1;
        }
        hasMoreBulk = bulkLineCursor < lineNumber;
        logApp.debug(`${logPrefix} read lines end on ${new Date().getTime() - startDate} ms; hasMoreBulk=${hasMoreBulk}; lineNumber=${lineNumber}`);

        if (lines.length > 0) {
          try {
            logApp.debug(`${logPrefix} generating bundle with ${lines.length} csv lines`);
            const generatedBundleCount = await generateBundlesAndSendToWorkers(context, lines, opts);
            totalBundleCount += generatedBundleCount;
          } catch (error: any) {
            const errorData = { error: error.message, source: `${fileId}, from ${lineNumber} and ${BULK_LINE_PARSING_NUMBER} following lines.` };
            logApp.error(error, { errorData });
            await reportExpectation(context, applicantUser, workId, errorData);
          }
        }
      } catch (error: any) {
        logApp.error(error);
        const errorData = { error: error.message, source: fileId };
        await reportExpectation(context, applicantUser, workId, errorData);
      } finally {
        rl.close();
      }
    }
  }
  logApp.info(`${logPrefix} processing CSV ${opts.fileId} DONE in ${new Date().getTime() - startDate2} ms for ${totalBundleCount} bundles.`);
  await updateProcessedTime(context, applicantUser, workId, `${totalBundleCount} generated bundle(s) for worker import`);
};

export const consumeQueueCallback = async (context: AuthContext, message: string) => {
  const messageParsed = JSON.parse(message);
  const workId = messageParsed.internal.work_id;
  const applicantId = messageParsed.internal.applicant_id ?? OPENCTI_SYSTEM_UUID;
  const fileId = messageParsed.event.file_id;
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
    const opts: ConsumerOpts = {
      workId,
      applicantUser,
      applicantId,
      csvMapper,
      entity,
      fileId
    };

    await updateReceivedTime(context, applicantUser, workId, 'Connector ready to process the operation');
    const validateBeforeImport = connectorConfig.config.validate_before_import;
    if (validateBeforeImport) {
      await processCSVforWorkbench(context, opts);
    } else {
      await processCSVforWorkers(context, opts);
    }
  } catch (error: any) {
    const errorData = { error: error.stack, source: fileId };
    logApp.error(error, { context, errorData });
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
          logApp.error(DatabaseError(`${logPrefix} Closing RabbitMQ connection failed`, { cause: e }));
        }
      }
      // TODO REMOVE TYPING, don't know why it's not working
      setTimeout(handleCsvImport as unknown as (args: void) => void, RETRY_CONNECTION_PERIOD);
    });
  };

  return {
    start: async () => {
      const context = executionContext(connectorConfig.id.toLowerCase());
      logApp.info(`${logPrefix} Starting ${connectorConfig.name} manager`);
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
      logApp.info(`${logPrefix} Stopping ${connectorConfig.name} manager`);
      if (rabbitMqConnection) rabbitMqConnection.close();
      return true;
    },
  };
};

const importCsvConnector = initImportCsvConnector();

export default importCsvConnector;
