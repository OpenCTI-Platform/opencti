import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router';
import { logs } from '@opentelemetry/api';
import { InMemoryLogRecordExporter, LoggerProvider, SimpleLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { ErrorBoundary } from './Error';
import { CHUNK_LOAD_FAILED_EVENT_NAME, CHUNK_RELOAD_EVENT_NAME, CHUNK_RELOAD_STORAGE_KEY, NETWORK_FAILED_EVENT_NAME } from '../../utils/logging/environmentFailures';
import { SEVERITY_NUMBERS } from '../../utils/logging/logger';

const Fallback = () => <div>fallback</div>;

const Thrower = ({ error }: { error: unknown }) => {
  throw error;
};

const renderFailing = (error: unknown) => render(
  <BrowserRouter>
    <ErrorBoundary display={Fallback}>
      <Thrower error={error} />
    </ErrorBoundary>
  </BrowserRouter>,
);

describe('ErrorBoundary logging', () => {
  let exporter: InMemoryLogRecordExporter;
  let provider: LoggerProvider;

  beforeEach(() => {
    sessionStorage.clear();
    // React reports every error a boundary catches on the console
    vi.spyOn(console, 'error').mockImplementation(() => {});
    exporter = new InMemoryLogRecordExporter();
    provider = new LoggerProvider({
      processors: [new SimpleLogRecordProcessor({ exporter })],
      loggerConfigurator: () => ({ enabled: true, minimumSeverity: SEVERITY_NUMBERS.DEBUG, traceBased: false }),
    });
    logs.setGlobalLoggerProvider(provider);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await provider.shutdown();
    logs.disable();
  });

  const loggedEvents = () => exporter.getFinishedLogRecords().map(({ eventName, severityNumber }) => ({ eventName, severityNumber }));

  it('reloads once on a chunk load error and logs it at warn', () => {
    renderFailing(new TypeError('Failed to fetch dynamically imported module: https://platform.example/assets/Root-AbCd1234.js'));

    expect(screen.getByText('fallback')).toBeInTheDocument();
    expect(sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY)).not.toBeNull();
    expect(loggedEvents()).toEqual([
      { eventName: CHUNK_RELOAD_EVENT_NAME, severityNumber: SEVERITY_NUMBERS.INFO },
      { eventName: CHUNK_LOAD_FAILED_EVENT_NAME, severityNumber: SEVERITY_NUMBERS.WARN },
    ]);
  });

  it('does not reload again when the chunk is still missing after a reload', () => {
    sessionStorage.setItem(CHUNK_RELOAD_STORAGE_KEY, String(Date.now()));

    renderFailing(new TypeError('Importing a module script failed.'));

    expect(screen.getByText('fallback')).toBeInTheDocument();
    expect(loggedEvents()).toEqual([
      { eventName: CHUNK_LOAD_FAILED_EVENT_NAME, severityNumber: SEVERITY_NUMBERS.WARN },
    ]);
  });

  it('logs a fetch rejected without response at warn', () => {
    renderFailing(new TypeError('Failed to fetch'));

    expect(loggedEvents()).toEqual([
      { eventName: NETWORK_FAILED_EVENT_NAME, severityNumber: SEVERITY_NUMBERS.WARN },
    ]);
    expect(sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY)).toBeNull();
  });

  it('does not log an error that carries an HTTP response', () => {
    renderFailing(Object.assign(new Error('Request failed'), { res: { status: 502 } }));

    expect(loggedEvents()).toEqual([]);
  });

  it('keeps logging any other error as a crash', () => {
    renderFailing(new TypeError('value.split is not a function'));

    expect(loggedEvents()).toEqual([
      { eventName: 'opencti.frontend.component_crashed', severityNumber: SEVERITY_NUMBERS.ERROR },
    ]);
  });
});
