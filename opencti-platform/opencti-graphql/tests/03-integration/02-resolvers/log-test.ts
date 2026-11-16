import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { addReport } from '../../../src/domain/report';
import { logApp, logFrontend } from '../../../src/config/conf';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { stixDomainObjectDelete, stixDomainObjectEditField } from '../../../src/domain/stixDomainObject';
import { awaitUntilCondition, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { utcDate } from '../../../src/utils/format';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

const READ_QUERY = gql`
  query Logs($first: Int, $filters: FilterGroup) {
    logs(first: $first, filters: $filters) {
      edges {
        node {
          id
          event_type
          event_scope
          context_data {
            message
            changes {
              field
              changes_removed
              changes_added
            }
          }
        }
      }
    }
  }
`;

describe('Log resolver standard behavior', async () => {
  let reportInternalId: string;

  beforeAll(async () => {
    const report = await addReport(testContext, ADMIN_USER, {
      name: 'Report2',
      published: utcDate(),
    });
    reportInternalId = report.id;
  });

  afterAll(async () => {
    await stixDomainObjectDelete(testContext, ADMIN_USER, reportInternalId, ENTITY_TYPE_CONTAINER_REPORT);
  });
  it('should log previous and value for description update', async () => {
    // Update description
    await stixDomainObjectEditField(testContext, ADMIN_USER, reportInternalId, [{ key: 'description', value: ['new description'] }]);

    // Wait until the log is available
    await awaitUntilCondition(async () => {
      const queryResult = await queryAsAdminWithSuccess({
        query: READ_QUERY,
        variables: {
          filters: {
            mode: 'and',
            filterGroups: [],
            filters: [
              {
                key: [
                  'context_data.id',
                ],
                values: [reportInternalId],
              },
            ],
          },
        },
      });
      return queryResult?.data?.logs.edges.length > 1; // we need create and update
    }, 10000);

    const queryResult = await queryAsAdminWithSuccess({
      query: READ_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [
            {
              key: [
                'context_data.id',
              ],
              values: [reportInternalId],
            },
          ],
        },
      },
    });

    const updateEvent = queryResult?.data?.logs.edges.find((item: any) => item.node.event_scope === 'update');
    const historyChange = updateEvent.node.context_data.changes[0];
    expect(historyChange).toEqual({
      field: 'Description',
      changes_removed: [],
      changes_added: ['new description'],
    });
  });
});

const FRONTEND_LOGS_ADD_MUTATION = gql`
  mutation FrontendLogsAdd($logs: [FrontendLogInput!]!) {
    frontendLogsAdd(logs: $logs)
  }
`;

const buildFrontendLog = (overrides = {}) => ({
  timestamp: '2026-10-20T10:00:00.000Z',
  level: 'WARN',
  message: 'Filter value is not a string',
  eventName: 'opencti.filter.value_not_string',
  data: { filter: { key: 'objectLabel' } },
  exception: null,
  ...overrides,
});

describe('Log resolver frontendLogsAdd', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should write each frontend log at its own level', async () => {
    const warnSpy = vi.spyOn(logFrontend, 'warn');
    const errorSpy = vi.spyOn(logFrontend, 'error');

    const queryResult = await queryAsAdminWithSuccess({
      query: FRONTEND_LOGS_ADD_MUTATION,
      variables: {
        logs: [
          buildFrontendLog(),
          buildFrontendLog({
            level: 'ERROR',
            message: 'Uncaught error',
            eventName: 'opencti.frontend.uncaught_error',
            data: null,
            exception: { type: 'TypeError', message: 'value.split is not a function', stacktrace: 'TypeError: value.split is not a function' },
          }),
        ],
      },
    });

    expect(queryResult?.data?.frontendLogsAdd).toBe(true);
    expect(warnSpy).toHaveBeenCalledWith('Filter value is not a string', {
      client_timestamp: new Date('2026-10-20T10:00:00.000Z'),
      event_name: 'opencti.filter.value_not_string',
      data: { filter: { key: 'objectLabel' } },
      exception: null,
    });
    expect(errorSpy).toHaveBeenCalledWith('Uncaught error', expect.objectContaining({
      event_name: 'opencti.frontend.uncaught_error',
      exception: { type: 'TypeError', message: 'value.split is not a function', stacktrace: 'TypeError: value.split is not a function' },
    }));
  });

  it('should keep the first 50 logs of a larger batch and warn about it', async () => {
    const infoSpy = vi.spyOn(logFrontend, 'info');
    const appWarnSpy = vi.spyOn(logApp, 'warn');

    await queryAsAdminWithSuccess({
      query: FRONTEND_LOGS_ADD_MUTATION,
      variables: { logs: Array.from({ length: 60 }, () => buildFrontendLog({ level: 'INFO' })) },
    });

    expect(infoSpy).toHaveBeenCalledTimes(50);
    expect(appWarnSpy).toHaveBeenCalledWith(
      '[FRONTEND LOGS] Batch larger than the frontend logger sends, extra records dropped',
      expect.objectContaining({ received: 60, max: 50, user_id: ADMIN_USER.id }),
    );
  });
});
