import { commitMutation, graphql } from 'react-relay';
import { ExportResultCode, hrTimeToMilliseconds } from '@opentelemetry/core';
import type { ExportResult } from '@opentelemetry/core';
import type { LogRecordExporter, ReadableLogRecord } from '@opentelemetry/sdk-logs';
import { environment } from '../../relay/environment';
import { SEVERITY_NUMBERS } from './logger';
import { toAppModule, toErrorDependency, toErrorOrigin } from './errorOrigin';
import type { LogLevel } from './logger';
import type { FrontendLogInput, GraphQLLogRecordExporterAddLogsMutation } from './__generated__/GraphQLLogRecordExporterAddLogsMutation.graphql';

const addLogsMutation = graphql`
  mutation GraphQLLogRecordExporterAddLogsMutation($logs: [FrontendLogInput!]!) {
    frontendLogsAdd(logs: $logs)
  }
`;

const toLevel = (severityText?: string): LogLevel => {
  return severityText && severityText in SEVERITY_NUMBERS ? (severityText as LogLevel) : 'ERROR';
};

const toText = (value: unknown) => (typeof value === 'string' && value.length > 0 ? value : undefined);

export const toFrontendLogInput = (record: ReadableLogRecord): FrontendLogInput => {
  const attributes = record.attributes ?? {};
  const type = toText(attributes['exception.type']);
  const message = toText(attributes['exception.message']);
  const stacktrace = toText(attributes['exception.stacktrace']);
  return {
    timestamp: new Date(hrTimeToMilliseconds(record.hrTime)).toISOString(),
    level: toLevel(record.severityText),
    message: String(record.body ?? ''),
    eventName: record.eventName ?? 'opencti.frontend.unnamed',
    data: attributes.data ?? null,
    exception: type || message || stacktrace ? { type, message, stacktrace } : null,
    origin: toErrorOrigin(attributes.origin),
    module: toAppModule(attributes.module),
    entryModule: toAppModule(attributes.entry_module),
    dependency: toErrorDependency(attributes.dependency),
  };
};

// Uses the Relay mutation API directly rather than the wrapper in relay/environment:
// a failure to ship a log record must stay silent and never notify the user.
export class GraphQLLogRecordExporter implements LogRecordExporter {
  export(records: ReadableLogRecord[], resultCallback: (result: ExportResult) => void): void {
    if (records.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }
    try {
      commitMutation<GraphQLLogRecordExporterAddLogsMutation>(environment, {
        mutation: addLogsMutation,
        variables: { logs: records.map(toFrontendLogInput) },
        onCompleted: () => resultCallback({ code: ExportResultCode.SUCCESS }),
        onError: (error) => resultCallback({ code: ExportResultCode.FAILED, error }),
      });
    } catch (error) {
      resultCallback({ code: ExportResultCode.FAILED, error: error as Error });
    }
  }

  async forceFlush(): Promise<void> {}

  async shutdown(): Promise<void> {}
}
