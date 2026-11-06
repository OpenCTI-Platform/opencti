import { describe, expect, it, vi } from 'vitest';
import type { IngestionHealthSummary_ingestionHealth$key } from './__generated__/IngestionHealthSummary_ingestionHealth.graphql';
import { readHealthIssue } from './IngestionHealthSummary';

// The fragment is read inline: the tests give its data directly
vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  readInlineData: (_fragment: unknown, key: unknown) => key,
}));

const blockingRuntime = { health_check_code: 'HEARTBEAT_MISSING', health_check_message: 'No heartbeat received', health_check_metadata: {}, health_check_kind: 'runtime', health_check_severity: 'blocking' };
const advisoryRuntime = { health_check_code: 'LAST_RUN_FAILED', health_check_message: 'Last run failed', health_check_metadata: {}, health_check_kind: 'runtime', health_check_severity: 'advisory' };
const advisoryConfiguration = { health_check_code: 'USER_NOT_SERVICE_ACCOUNT', health_check_message: 'User is not a service account', health_check_metadata: {}, health_check_kind: 'configuration', health_check_severity: 'advisory' };

const healthOf = (status: string, healthChecks: object[]) => ({ status, healthChecks }) as unknown as IngestionHealthSummary_ingestionHealth$key;

describe('readHealthIssue', () => {
  it('should show the first check of the severity of the status, the other failing checks counted whatever their severity', () => {
    const issue = readHealthIssue(healthOf('critical', [advisoryConfiguration, blockingRuntime, advisoryRuntime]));
    expect(issue).toEqual({ severity: 'critical', check: blockingRuntime, othersCount: 2 });
  });

  it('should count no other check when no check of the severity of the status is shown: there is no check to show them next to', () => {
    const issue = readHealthIssue(healthOf('critical', [advisoryConfiguration, advisoryRuntime]));
    expect(issue).toEqual({ severity: 'critical', check: null, othersCount: 0 });
  });

  it('should show a degraded issue from its advisory checks', () => {
    const issue = readHealthIssue(healthOf('degraded', [advisoryRuntime, advisoryConfiguration]));
    expect(issue).toEqual({ severity: 'degraded', check: advisoryRuntime, othersCount: 1 });
  });

  it.each(['healthy', 'unknown'])('should flag nothing for a %s status', (status) => {
    expect(readHealthIssue(healthOf(status, []))).toBeNull();
  });

  it('should flag nothing without health: not evaluated yet, or stopped', () => {
    expect(readHealthIssue(null)).toBeNull();
  });
});
