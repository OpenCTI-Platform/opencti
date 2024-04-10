import fs from 'node:fs';
import { InMemoryLogRecordExporter, LogRecord } from '@opentelemetry/sdk-logs';
import type { ExportResult } from '@opentelemetry/core/build/src/ExportResult';

export const FILE_EXPORTER_PATH = '../../../../Documents/fileExporter.txt';

export class FileExporter extends InMemoryLogRecordExporter {
  constructor(filePath: string) {
    super();
    this.filePath = filePath;
  }

  private filePath;

  export(logs: LogRecord[], resultCallback: (callback: ExportResult) => void) {
    console.log('IN EXPORTER');
    console.log('logs', logs);
    const formattedLogs = logs.map((log) => ({
      body: log.body,
      date: new Date(log.attributes.timestamp as number),
    }));
    fs.appendFile(
      this.filePath,
      `${JSON.stringify(formattedLogs)}\n`,
      (err) => {
        if (err) {
          console.log('err', err);
          return resultCallback({ code: 1, error: err });
        }
        console.log('OK');
        return resultCallback({ code: 0 });
      }
    );
  }
}
