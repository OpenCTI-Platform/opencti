import { Readable } from 'stream';
import * as readline from 'node:readline';
import type { SdkStream } from '@smithy/types/dist-types/serde';
import conf, { logApp } from '../../config/conf';
import { executionContext } from '../../utils/access';
import type { AuthContext, AuthUser } from '../../types/user';
import { consumeQueue, pushToWorkerForConnector, registerConnectorQueues } from '../../database/rabbitmq';
import { downloadFile } from '../../database/file-storage';
import { reportExpectation, updateExpectationsNumber, updateProcessedTime, updateReceivedTime } from '../../domain/work';
import { bundleProcessV2 } from '../../parser/csv-bundler';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { resolveUserByIdFromCache } from '../../domain/user';
import { parseCsvMapper } from '../../modules/internal/csvMapper/csvMapper-utils';
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

const generateBundle = async (context: AuthContext, csvMapper: CsvMapperParsed, messageParsed: any, entity: BasicStoreBase | undefined, csvLines: string[]) => {
  const workId = messageParsed.internal.work_id;
  const applicantId = messageParsed.internal.applicant_id;
  const applicantUser = await resolveUserByIdFromCache(context, applicantId) as AuthUser;
  const bundlesBuilder: BundleBuilder[] = await bundleProcessV2(context, applicantUser, csvLines, csvMapper, { entity });


  const validateBeforeImport = connectorConfig.config.validate_before_import;
  if (validateBeforeImport) {
    await updateExpectationsNumber(context, applicantUser, workId, 1);
    const contentStream = Readable.from([JSON.stringify(bundlesBuilder[0], null, '  ')]); // FIXME bundlesBuilder[0]
    const file = {
      createReadStream: () => contentStream,
      filename: `${workId}.json`,
      mimetype: 'application/json',
    };
    await uploadToStorage(context, applicantUser, 'import/pending', file, { entity });
    await reportExpectation(context, applicantUser, workId);
    throw FunctionalError('Not implemented yet'); // FIXME just to be sure that we don't merge without that
  } else {
    logApp.info(`ANGIE bundlesBuilder count:${bundlesBuilder.length}`);

    for (let i = 0; i < bundlesBuilder.length; i += 1) {
      const bundle = bundlesBuilder[i].build();
      logApp.info(`ANGIE current bundle count:${bundle.objects.length}`);
      const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
      if (bundle.objects.length > 0) {
        await pushToWorkerForConnector(connector.internal_id, {
          type: 'bundle',
          update: true,
          applicant_id: applicantId ?? OPENCTI_SYSTEM_UUID,
          work_id: workId,
          content
        });
      }
    }
  }
};

export const consumeQueueCallback = async (context: AuthContext, message: string) => {
  const messageParsed = JSON.parse(message);
  const workId = messageParsed.internal.work_id;
  const applicantId = messageParsed.internal.applicant_id;
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
          if (lines.length >= BULK_LINE_PARSING_NUMBER) {
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
          logApp.error(DatabaseError('Closing RabbitMQ connection failed', { cause: e }));
        }
      }
      // TODO REMOVE TYPING, don't know why it's not working
      setTimeout(handleCsvImport as unknown as (args: void) => void, RETRY_CONNECTION_PERIOD);
    });
  };

  return {
    start: async () => {
      const context = executionContext(connectorConfig.id.toLowerCase());
      logApp.info(`[OPENCTI-MODULE] Starting ${connectorConfig.name} manager`);
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
      logApp.info(`[OPENCTI-MODULE] Stopping ${connectorConfig.name} manager`);
      if (rabbitMqConnection) rabbitMqConnection.close();
      return true;
    },
  };
};

const importCsvConnector = initImportCsvConnector();

export default importCsvConnector;
