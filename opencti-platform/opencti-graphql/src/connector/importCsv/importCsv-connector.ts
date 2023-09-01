import type { SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { Readable } from 'stream';
import type { SdkStream } from '@smithy/types/dist-types/serde';
import conf, { logApp } from '../../config/conf';
import { executionContext } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { consumeQueue, existsConnectorQueues, pushToSync, registerConnectorQueues } from '../../database/rabbitmq';
import { downloadFile, upload } from '../../database/file-storage';
import {
  reportExpectation,
  updateExpectationsNumber,
  updateProcessedTime,
  updateReceivedTime
} from '../../domain/work';
import { bundleProcess } from '../../parser/csv-bundler';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { resolveUserById } from '../../domain/user';
import { parseCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
import type { ConnectorConfig } from '../connector';
import { IMPORT_CSV_CONNECTOR } from './importCsv';

const connectorConfig: ConnectorConfig = {
  id: 'IMPORT_CSV_BUILT_IN_CONNECTOR',
  name: 'Import Csv built in connector',
  running: false,
  config: {
    enable: conf.get('import_csv_built_in_connector:enabled'),
    validate_before_import: conf.get('import_csv_built_in_connector:validate_before_import'),
    scheduleTime: conf.get('import_csv_built_in_connector:interval'),
  }
};

const initImportCsvConnector = () => {
  const { config } = connectorConfig;
  let scheduler: SetIntervalAsyncTimer<unknown[]>;
  const connector = IMPORT_CSV_CONNECTOR;

  const consumeQueueCallback = async (context: AuthContext, message: string) => {
    const messageParsed = JSON.parse(message);
    const workId = messageParsed.internal.work_id;
    const applicantId = messageParsed.internal.applicant_id;
    const fileId = messageParsed.event.file_id;
    const applicantUser = await resolveUserById(context, applicantId);

    try {
      const csvMapper = parseCsvMapper(JSON.parse(messageParsed.configuration));
      const stream: SdkStream<Readable> | null | undefined = await downloadFile(fileId) as SdkStream<Readable> | null | undefined;

      await updateReceivedTime(context, applicantUser, workId, 'Connector ready to process the operation');

      if (stream) {
        const chunks: Uint8Array[] = [];
        stream.on('data', async (chunk) => {
          chunks.push(chunk.toString('utf8'));
        }).on('error', (err) => {
          throw err;
        })
          .on('end', async () => {
            const string = chunks.join('');
            const bundle = await bundleProcess(context, applicantUser, Buffer.from(string), csvMapper);
            await updateExpectationsNumber(context, applicantUser, workId, 1);

            const validateBeforeImport = connectorConfig.config.validate_before_import;
            if (validateBeforeImport) {
              const contentStream = Readable.from([JSON.stringify(bundle, null, '  ')]);
              const file = {
                createReadStream: () => contentStream,
                filename: `${workId}.json`,
                mimetype: 'application/json',
              };
              await upload(context, applicantUser, 'import/pending', file, {});

              await reportExpectation(context, applicantUser, workId);
            } else {
              const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
              await pushToSync({
                type: 'bundle',
                update: true,
                applicant_id: applicantId ?? OPENCTI_SYSTEM_UUID,
                work_id: workId,
                content
              });
            }
          });
      }

      await updateProcessedTime(context, applicantUser, workId, ' generated bundle(s) for worker import');
    } catch (error: any) {
      const errorData = {
        error: error.stack,
        source: fileId,
      };
      await reportExpectation(context, applicantUser, workId, errorData);
    }
  };

  const handler = async (context: AuthContext) => {
    try {
      connectorConfig.running = true;
      await consumeQueue(context, connector.id, consumeQueueCallback);
    } catch (e: any) {
      logApp.error(`[OPENCTI-MODULE] ${connectorConfig.name} manager failed to start`, { error: e });
    } finally {
      connectorConfig.running = false;
      logApp.debug(`[OPENCTI-MODULE] ${connectorConfig.name} manager done`);
    }
  };

  return {
    start: async () => {
      logApp.info(`[OPENCTI-MODULE] Starting ${connectorConfig.name} manager`);

      const context = executionContext(connectorConfig.id.toLowerCase());
      // Register connector queues if not exists
      const cbError = async (error: any) => {
        if (error) await registerConnectorQueues(connector.id, connector.name, connector.connector_type, connector.connector_scope);
      };
      await existsConnectorQueues(connector.id, cbError);
      // Polling
      scheduler = setIntervalAsync(async () => {
        await handler(context);
      }, config.scheduleTime);
    },
    status: () => {
      return {
        id: connectorConfig.id,
        enable: config.enable ?? false,
        running: connectorConfig.running,
      };
    },
    shutdown: async () => {
      logApp.info(`[OPENCTI-MODULE] Stopping ${connectorConfig.name} manager`);

      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};

const importCsvConnector = initImportCsvConnector();

export default importCsvConnector;
