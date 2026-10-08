import { describe, expect, it } from 'vitest';
import { toFrontendLogEntry } from '../../../src/config/frontend-log';
import { APP_MODULE, DEPENDENCIES, ERROR_ORIGINS } from '../../../src/config/error-origin';
import { AppModule, ErrorDependency, ErrorOrigin, FrontendLogLevel } from '../../../src/generated/graphql';

const baseLog = {
  timestamp: '2026-10-07T10:00:00.000Z',
  level: FrontendLogLevel.Error,
  message: 'React component tree crashed',
  eventName: 'opencti.frontend.component_crashed',
};

describe('frontend log entry (RFC 0006)', () => {
  it('should keep the level of a record the UI did not classify', () => {
    expect(toFrontendLogEntry({ ...baseLog, level: FrontendLogLevel.Warn })).toEqual({
      level: 'warn',
      message: 'React component tree crashed',
      meta: { client_timestamp: baseLog.timestamp, event_name: baseLog.eventName, data: undefined, exception: undefined },
    });
  });

  it('should log a code fault of the UI at error, with its module', () => {
    const entry = toFrontendLogEntry({ ...baseLog, origin: ErrorOrigin.Code, module: AppModule.Catalog, entryModule: AppModule.Catalog });
    expect(entry.level).toBe('error');
    expect(entry.meta).toMatchObject({ origin: 'code', module: 'catalog', entry_module: 'catalog' });
  });

  it('should log an unreachable API at warn, whatever level the UI sent', () => {
    const entry = toFrontendLogEntry({ ...baseLog, origin: ErrorOrigin.Infra, dependency: ErrorDependency.Api, entryModule: AppModule.Catalog });
    expect(entry.level).toBe('warn');
    expect(entry.meta).toMatchObject({ origin: 'infra', dependency: 'api', entry_module: 'catalog' });
  });

  it('should drop a dependency sent without an infra origin', () => {
    const entry = toFrontendLogEntry({ ...baseLog, origin: ErrorOrigin.Code, dependency: ErrorDependency.Api });
    expect(entry.meta).not.toHaveProperty('dependency');
  });
});

// The GraphQL enums are what the UI can send: they must stay the same closed lists as the backend's.
describe('enums shared with the UI', () => {
  it('should match the backend enums', () => {
    expect(Object.values(AppModule).sort()).toEqual(Object.values(APP_MODULE).sort());
    expect(Object.values(ErrorOrigin).sort()).toEqual([...ERROR_ORIGINS].sort());
    expect(Object.values(ErrorDependency).sort()).toEqual([...DEPENDENCIES].sort());
  });
});
