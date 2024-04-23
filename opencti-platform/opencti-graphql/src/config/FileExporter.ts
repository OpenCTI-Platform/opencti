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
    const formattedLogs = logs.map((log) => log.body);
    fs.appendFile(
      this.filePath,
      `${JSON.stringify(formattedLogs)}\n`,
      (err) => {
        if (err) {
          return resultCallback({ code: 1, error: err });
        }
        return resultCallback({ code: 0 });
      }
    );
  }
}
