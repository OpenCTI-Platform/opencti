import { Readable } from 'stream';
import * as readline from 'node:readline';
import type { SdkStream } from '@smithy/types/dist-types/serde';
import conf, { logApp } from '../../config/conf';
import { executionContext } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import { consumeQueue, pushToSync, registerConnectorQueues } from '../../database/rabbitmq';
import { downloadFile } from '../../database/file-storage';
import { reportExpectation, updateExpectationsNumber, updateProcessedTime, updateReceivedTime } from '../../domain/work';
import { bundleProcess } from '../../parser/csv-bundler';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { resolveUserByIdFromCache } from '../../domain/user';
import { parseCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
import type { ConnectorConfig } from '../connector';
import { IMPORT_CSV_CONNECTOR } from './importCsv';
import { internalLoadById } from '../../database/middleware-loader';
import { FunctionalError } from '../../config/errors';
import { uploadToStorage } from '../../database/file-storage-helper';
import type { CsvMapperParsed } from '../../modules/internal/csvMapper/csvMapper-types';
import type { BasicStoreBase } from '../../types/store';

const RETRY_CONNECTION_PERIOD = 10000;
const BULK_LINE_PARSING_NUMBER = conf.get('import_csv_built_in_connector:bulk_creation_size') || 5000;

const connectorConfig: ConnectorConfig = {
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
  let rabbitMqConnection: { close: () => void };

  const connectionSetterCallback = (conn: any) => {
    rabbitMqConnection = conn;
  };

  const generateBundle = async (context: AuthContext, csvMapper: CsvMapperParsed, messageParsed: any, entity: BasicStoreBase | undefined, csvLines: string[]) => {
    const workId = messageParsed.internal.work_id;
    const applicantId = messageParsed.internal.applicant_id;
    const applicantUser = await resolveUserByIdFromCache(context, applicantId) as AuthUser;
    const bundle = await bundleProcess(context, applicantUser, csvLines, csvMapper, { entity });
    const validateBeforeImport = connectorConfig.config.validate_before_import;
    if (validateBeforeImport) {
      await updateExpectationsNumber(context, applicantUser, workId, 1);
      const contentStream = Readable.from([JSON.stringify(bundle, null, '  ')]);
      const file = {
        createReadStream: () => contentStream,
        filename: `${workId}.json`,
        mimetype: 'application/json',
      };
      await uploadToStorage(context, applicantUser, 'import/pending', file, { entity });
      await reportExpectation(context, applicantUser, workId);
    } else {
      await updateExpectationsNumber(context, applicantUser, workId, bundle.objects.length);
      const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
      await pushToSync({
        type: 'bundle',
        update: true,
        applicant_id: applicantId ?? OPENCTI_SYSTEM_UUID,
        work_id: workId,
        content
      });
    }
  };

  const consumeQueueCallback = async (context: AuthContext, message: string) => {
    const messageParsed = JSON.parse(message);
    const workId = messageParsed.internal.work_id;
    const applicantId = messageParsed.internal.applicant_id;
    const fileId = messageParsed.event.file_id;
    const applicantUser = await resolveUserByIdFromCache(context, applicantId) as AuthUser;
    const entityId = messageParsed.event.entity_id;
    const entity = entityId ? await internalLoadById(context, applicantUser, entityId) : undefined;
    let parsedConfiguration;
    try {
      parsedConfiguration = JSON.parse(messageParsed.configuration);
    } catch (error) {
      throw FunctionalError('Could not parse CSV mapper configuration', { error });
    }

    try {
      const csvMapper = parseCsvMapper(parsedConfiguration);
      const stream: SdkStream<Readable> | null | undefined = await downloadFile(fileId) as SdkStream<Readable> | null | undefined;
      await updateReceivedTime(context, applicantUser, workId, 'Connector ready to process the operation');
      if (stream) {
        let lines: string[] = [];
        const rl = readline.createInterface({ input: stream, crlfDelay: 5000 });
        try {
          // Need an async interator to prevent blocking
          // eslint-disable-next-line no-restricted-syntax
          for await (const line of rl) {
            lines.push(line);
            // Only create bundle with a limited size to prevent OOM
            if (lines.length > BULK_LINE_PARSING_NUMBER) {
              await generateBundle(context, csvMapper, messageParsed, entity, lines);
              lines = [];
            }
          }
          if (lines.length > 0) {
            await generateBundle(context, csvMapper, messageParsed, entity, lines);
          }
        } catch (error: any) {
          const errorData = { error: error.message, source: fileId };
          await reportExpectation(context, applicantUser, workId, errorData);
        }
      }
      await updateProcessedTime(context, applicantUser, workId, ' generated bundle(s) for worker import');
    } catch (error: any) {
      const errorData = { error: error.stack, source: fileId };
      await reportExpectation(context, applicantUser, workId, errorData);
    }
  };

  const handleCsvImport = (context: AuthContext) => {
    // Promise is not awaited as consumeQueue maintains the connection with rabbitMQ
    consumeQueue(context, connector.id, connectionSetterCallback, consumeQueueCallback).catch((err) => {
      logApp.error('[IMPORT-CSV] Error in queue consumption', { cause: err });
      // In case of broken connection, try to close the connection and retry to connect to the queue.
      if (rabbitMqConnection) {
        try {
          rabbitMqConnection.close();
        } catch (e) {
          // Connection already closed
        }
      }
      // After retry period, restart the connection
      setTimeout(() => handleCsvImport(context), RETRY_CONNECTION_PERIOD);
    });
  };

  return {
    start: async () => {
      const context = executionContext(connectorConfig.id.toLowerCase());
      logApp.info(`[OPENCTI-MODULE] Starting ${connectorConfig.name} manager`);
      await registerConnectorQueues(connector.id, connector.name, connector.connector_type, connector.connector_scope);
      handleCsvImport(context);
    },
    status: () => {
      return {
        id: connectorConfig.id,
        enable: config.enable ?? false,
        running: config.enable ?? false,
      };
    },
    shutdown: async () => {
      logApp.info(`[OPENCTI-MODULE] Stopping ${connectorConfig.name} manager`);
      if (rabbitMqConnection) {
        rabbitMqConnection.close();
      }
      return true;
    },
  };
};

const importCsvConnector = initImportCsvConnector();

export default importCsvConnector;
