import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext, USER_CONNECTOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUser, queryAsUserWithSuccess } from '../../utils/testQueryHelper';
import { deleteElementById, patchAttribute } from '../../../src/database/middleware';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import { MARKING_TLP_RED } from '../../../src/schema/identifier';
import { ENTITY_TYPE_CONNECTOR } from '../../../src/schema/internalObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ENTITY_TYPE_HUNT_RUN } from '../../../src/modules/hunt/huntRun/huntRun-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../src/modules/securityPlatform/securityPlatform-types';
import { HUNT_MESSAGES } from '../../../src/modules/hunt/hunt-messages';

const CONNECTOR_ID = '7d1f6c2e-3b4a-4e5f-8a9b-0c1d2e3f4a51';
const SECURITY_PLATFORM_NAME = 'Indicator hunt test Splunk';
const SIGMA_RULE = `title: Indicator hunt test rule
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
`;

const READINESS = 'readiness { ready items { key status template values { name value } message } }';
const HUNT_ADD = gql`
  mutation HuntAdd($input: HuntAddInput!) { huntAdd(input: $input) { id hunt_type hunt_status ${READINESS} } }
`;
const HUNT_READ = gql`
  query Hunt($id: String!) {
    hunt(id: $id) {
      id
      hunt_status
      hunt_ioc_values { observable_type value }
      ${READINESS}
      iocSet(first: 10) { iocs_count restricted_count unsupported_count truncated iocs { key observable_type value sources { id entity_type } } }
    }
  }
`;
const HUNT_FIELD_PATCH = gql`
  mutation HuntFieldPatch($id: ID!, $input: [EditInput]!) { huntFieldPatch(id: $id, input: $input) { id hunt_status } }
`;
const HUNT_RUN_START = gql`
  mutation HuntRunStart($id: ID!) { huntRunStart(id: $id) { id hunt_run_status connector_id } }
`;
const HUNT_RUN_REPORT = gql`
  mutation HuntRunReport($id: ID!, $input: HuntRunReportInput!) { huntRunReport(id: $id, input: $input) { id hunt_run_status verdict hits_count } }
`;
const HUNT_RUN_READ = gql`
  query HuntRun($id: String!) {
    huntRun(id: $id) {
      id
      verdict
      hits_count
      ioc_results { key value observable_type verdict hits_count first_seen last_seen hosts reason deployed sources { id } }
    }
  }
`;
const HUNT_CONNECTOR_REGISTER = gql`
  mutation HuntConnectorRegister($input: HuntConnectorRegisterInput!) {
    huntConnectorRegister(input: $input) { id supports_indicators securityPlatform { id } }
  }
`;

type ReadinessItem = { key: string; status: string; template: string; message: string };
const itemOf = (items: ReadinessItem[], key: string) => items.filter((item) => item.key === key);

const reportAsConnector = async (runId: string, input: Record<string, unknown>) => {
  const run = await internalLoadById<BasicStoreEntity & { work_id?: string }>(testContext, ADMIN_USER, runId, { type: ENTITY_TYPE_HUNT_RUN });
  return queryAsUserWithSuccess(USER_CONNECTOR, { query: HUNT_RUN_REPORT, variables: { id: runId, input: { work_id: run?.work_id, ...input } } });
};

const registerHuntPlatform = async (supportsIndicators: boolean) => {
  const registration = await queryAsUserWithSuccess(USER_CONNECTOR, {
    query: HUNT_CONNECTOR_REGISTER,
    variables: { input: { connector_id: CONNECTOR_ID, platform: 'splunk', languages: ['spl'], security_platform_name: SECURITY_PLATFORM_NAME, supports_indicators: supportsIndicators } },
  });
  resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  return registration.data?.huntConnectorRegister;
};

describe('Hunt readiness and indicator hunts', () => {
  let securityPlatformId: string;
  let indicatorId: string;
  let restrictedIndicatorId: string;
  let observableId: string;
  let reportId: string;
  let indicatorHuntId: string;
  const huntIds: string[] = [];
  const scope = () => JSON.stringify({ mode: 'and', filters: [{ key: ['id'], values: [securityPlatformId], operator: 'eq', mode: 'or' }], filterGroups: [] });

  beforeAll(async () => {
    await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: gql`mutation RegisterConnector($input: RegisterConnectorInput) { registerConnector(input: $input) { id } }`,
      variables: { input: { id: CONNECTOR_ID, name: 'Indicator hunt test connector', type: 'INTERNAL_HUNT', scope: ['splunk'], auto: false, only_contextual: false } },
    });
    const connector = await registerHuntPlatform(false);
    securityPlatformId = connector.securityPlatform.id;
    const indicator = await queryAsAdminWithSuccess({
      query: gql`mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }`,
      variables: { input: { name: 'Indicator hunt test IP', pattern: "[ipv4-addr:value = '198.51.100.71']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr' } },
    });
    indicatorId = indicator.data?.indicatorAdd.id;
    const restricted = await queryAsAdminWithSuccess({
      query: gql`mutation IndicatorAdd($input: IndicatorAddInput!) { indicatorAdd(input: $input) { id } }`,
      variables: { input: { name: 'Indicator hunt test red IP', pattern: "[ipv4-addr:value = '198.51.100.72']", pattern_type: 'stix', x_opencti_main_observable_type: 'IPv4-Addr', objectMarking: [MARKING_TLP_RED] } },
    });
    restrictedIndicatorId = restricted.data?.indicatorAdd.id;
    const observable = await queryAsAdminWithSuccess({
      query: gql`mutation ObservableAdd($type: String!, $DomainName: DomainNameAddInput) { stixCyberObservableAdd(type: $type, DomainName: $DomainName) { id } }`,
      variables: { type: 'Domain-Name', DomainName: { value: 'indicator-hunt-test.example.com' } },
    });
    observableId = observable.data?.stixCyberObservableAdd.id;
    const report = await queryAsAdminWithSuccess({
      query: gql`mutation ReportAdd($input: ReportAddInput!) { reportAdd(input: $input) { id } }`,
      variables: { input: { name: 'Indicator hunt test report', published: '2026-10-01T00:00:00.000Z', objects: [observableId, restrictedIndicatorId] } },
    });
    reportId = report.data?.reportAdd.id;
  });

  afterAll(async () => {
    for (let index = 0; index < huntIds.length; index += 1) {
      await queryAsAdmin({ query: gql`mutation HuntDelete($id: ID!) { huntDelete(id: $id) }`, variables: { id: huntIds[index] } });
    }
    await queryAsAdmin({ query: gql`mutation DeleteConnector($id: ID!) { deleteConnector(id: $id) }`, variables: { id: CONNECTOR_ID } });
    await queryAsAdmin({ query: gql`mutation ReportDelete($id: ID!) { reportEdit(id: $id) { delete } }`, variables: { id: reportId } });
    for (const id of [indicatorId, restrictedIndicatorId]) {
      await queryAsAdmin({ query: gql`mutation IndicatorDelete($id: ID!) { indicatorDelete(id: $id) }`, variables: { id } });
    }
    await queryAsAdmin({ query: gql`mutation ObservableDelete($id: ID!) { stixCyberObservableEdit(id: $id) { delete } }`, variables: { id: observableId } });
    if (securityPlatformId) {
      await deleteElementById(testContext, ADMIN_USER, securityPlatformId, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
    }
  });

  it('should explain what a draft hunt misses and refuse its activation with the same sentence', async () => {
    const created = await queryAsAdminWithSuccess({ query: HUNT_ADD, variables: { input: { name: 'Readiness test draft', hunt_status: 'draft', hunt_scope: scope() } } });
    const hunt = created.data?.huntAdd;
    huntIds.push(hunt.id);
    expect(hunt.readiness.ready).toBe(false);
    expect(itemOf(hunt.readiness.items, 'logic')).toEqual([expect.objectContaining({ status: 'unmet', template: HUNT_MESSAGES.logicTelemetryMissing })]);
    expect(itemOf(hunt.readiness.items, 'connector')[0]).toMatchObject({ status: 'met', template: HUNT_MESSAGES.connectorReady });
    expect(itemOf(hunt.readiness.items, 'schedule')[0]).toMatchObject({ status: 'met', template: HUNT_MESSAGES.scheduleManual });
    expect(itemOf(hunt.readiness.items, 'scope')[0]).toMatchObject({ status: 'met', template: HUNT_MESSAGES.scopePlatforms });
    const refused = await queryAsAdmin({ query: HUNT_FIELD_PATCH, variables: { id: hunt.id, input: [{ key: 'hunt_status', value: ['active'] }] } });
    expect(refused.errors?.[0].message).toEqual(`This hunt cannot be activated: ${HUNT_MESSAGES.logicTelemetryMissing}`);
    // An invalid rule is reported with the errors of the platform
    const invalid = await queryAsAdmin({ query: HUNT_FIELD_PATCH, variables: { id: hunt.id, input: [{ key: 'sigma_rule', value: ['title: broken'] }] } });
    expect(invalid.errors?.[0].message).toContain('Invalid Sigma rule:');
    await queryAsAdminWithSuccess({ query: HUNT_FIELD_PATCH, variables: { id: hunt.id, input: [{ key: 'sigma_rule', value: [SIGMA_RULE] }] } });
    const ready = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: hunt.id } });
    expect(ready.data?.hunt.readiness.ready).toBe(true);
    expect(itemOf(ready.data?.hunt.readiness.items, 'logic')[0]).toMatchObject({ status: 'met', template: HUNT_MESSAGES.sigmaValid });
    const activated = await queryAsAdminWithSuccess({ query: HUNT_FIELD_PATCH, variables: { id: hunt.id, input: [{ key: 'hunt_status', value: ['active'] }] } });
    expect(activated.data?.huntFieldPatch.hunt_status).toEqual('active');
  });

  it('should refuse to activate a hunt whose scope matches no security platform', async () => {
    const emptyScope = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: ['No platform has this name'], operator: 'eq', mode: 'or' }], filterGroups: [] });
    const created = await queryAsAdminWithSuccess({ query: HUNT_ADD, variables: { input: { name: 'Readiness test empty scope', hunt_status: 'draft', sigma_rule: SIGMA_RULE, hunt_scope: emptyScope } } });
    huntIds.push(created.data?.huntAdd.id);
    const items = created.data?.huntAdd.readiness.items as ReadinessItem[];
    expect(itemOf(items, 'scope')[0]).toMatchObject({ status: 'unmet', template: HUNT_MESSAGES.scopeEmpty });
    expect(itemOf(items, 'connector')[0]).toMatchObject({ status: 'unmet', template: HUNT_MESSAGES.connectorMissing });
    const refused = await queryAsAdmin({ query: HUNT_FIELD_PATCH, variables: { id: created.data?.huntAdd.id, input: [{ key: 'hunt_status', value: ['active'] }] } });
    expect(refused.errors?.[0].message).toEqual(`This hunt cannot be activated: ${HUNT_MESSAGES.connectorMissing}`);
  });

  it('should resolve the values of an indicator hunt and leave out what its readers cannot see', async () => {
    const created = await queryAsAdminWithSuccess({
      query: HUNT_ADD,
      variables: {
        input: {
          name: 'Indicator hunt test',
          hunt_type: 'indicators',
          hunt_status: 'draft',
          hunt_scope: scope(),
          huntSources: [indicatorId, reportId],
          hunt_ioc_values: [{ observable_type: 'StixFile', value: 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855' }],
        },
      },
    });
    indicatorHuntId = created.data?.huntAdd.id;
    huntIds.push(indicatorHuntId);
    expect(created.data?.huntAdd.hunt_type).toEqual('indicators');
    const read = await queryAsAdminWithSuccess({ query: HUNT_READ, variables: { id: indicatorHuntId } });
    const hunt = read.data?.hunt;
    expect(hunt.hunt_ioc_values).toEqual([{ observable_type: 'StixFile', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }]);
    // The indicator, the domain of the report and the pasted hash; the red indicator of the report is left out
    expect(hunt.iocSet.iocs_count).toEqual(3);
    expect(hunt.iocSet.restricted_count).toEqual(1);
    expect(hunt.iocSet.iocs.map((ioc: { value: string }) => ioc.value).sort()).toEqual([
      '198.51.100.71',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'indicator-hunt-test.example.com',
    ]);
    const items = hunt.readiness.items as ReadinessItem[];
    expect(itemOf(items, 'logic').map((item) => [item.status, item.template])).toEqual([
      ['met', HUNT_MESSAGES.iocCount],
      ['warning', HUNT_MESSAGES.iocRestricted],
    ]);
    // The connector of the platform does not look up indicators yet
    expect(itemOf(items, 'connector')[0]).toMatchObject({ status: 'unmet', template: HUNT_MESSAGES.connectorIndicatorsMissing });
    const refused = await queryAsAdmin({ query: HUNT_FIELD_PATCH, variables: { id: indicatorHuntId, input: [{ key: 'hunt_status', value: ['active'] }] } });
    expect(refused.errors?.[0].message).toEqual(`This hunt cannot be activated: ${HUNT_MESSAGES.connectorIndicatorsMissing}`);
    const pasted = await queryAsAdmin({ query: HUNT_FIELD_PATCH, variables: { id: indicatorHuntId, input: [{ key: 'hunt_ioc_values', value: [{ observable_type: 'IPv4-Addr', value: 'not an address' }] }] } });
    expect(pasted.errors?.[0].message).toContain('Pasted value 1 is not a valid IPv4-Addr');
  });

  it('should run an indicator hunt on a connector that looks up indicators and record a verdict per value', async () => {
    const connector = await registerHuntPlatform(true);
    expect(connector.supports_indicators).toBe(true);
    await queryAsAdminWithSuccess({ query: HUNT_FIELD_PATCH, variables: { id: indicatorHuntId, input: [{ key: 'hunt_status', value: ['active'] }] } });
    const started = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: indicatorHuntId } });
    const [run] = started.data?.huntRunStart ?? [];
    expect(run.connector_id).toEqual(CONNECTOR_ID);
    const dispatched = await queryAsAdminWithSuccess({ query: HUNT_RUN_READ, variables: { id: run.id } });
    const snapshot = dispatched.data?.huntRun.ioc_results as { key: string; value: string; verdict: string; sources: { id: string }[] }[];
    expect(snapshot.map((result) => result.verdict)).toEqual(['pending', 'pending', 'pending']);
    const byValue = new Map(snapshot.map((result) => [result.value, result]));
    expect(byValue.get('198.51.100.71')?.sources.map((source) => source.id)).toEqual([indicatorId]);
    expect(byValue.get('indicator-hunt-test.example.com')?.sources.map((source) => source.id)).toEqual([observableId]);
    await reportAsConnector(run.id, { status: 'running' });
    const completed = await reportAsConnector(run.id, {
      status: 'completed',
      truncated: false,
      ioc_results: [
        { key: byValue.get('198.51.100.71')?.key, seen: true, hits_count: 14, first_seen: '2026-10-04T08:00:00.000Z', last_seen: '2026-10-04T09:30:00.000Z', hosts: ['WKS-01'] },
        { key: byValue.get('indicator-hunt-test.example.com')?.key, seen: false, hits_count: 0 },
        { key: byValue.get('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')?.key, searched: false, seen: false, reason: 'File hashes are not indexed on this platform' },
      ],
    });
    // Hits were seen: the run waits for a human verdict, its hits count is the sum of the values
    expect(completed.data?.huntRunReport).toMatchObject({ hunt_run_status: 'completed', verdict: 'pending', hits_count: 14 });
    const results = (await queryAsAdminWithSuccess({ query: HUNT_RUN_READ, variables: { id: run.id } })).data?.huntRun.ioc_results as Record<string, unknown>[];
    const resultOf = (value: string) => results.find((result) => result.value === value);
    expect(resultOf('198.51.100.71')).toMatchObject({ verdict: 'seen', hits_count: 14, hosts: ['WKS-01'], deployed: false });
    expect(new Date(resultOf('198.51.100.71')?.first_seen as string).toISOString()).toEqual('2026-10-04T08:00:00.000Z');
    expect(resultOf('indicator-hunt-test.example.com')).toMatchObject({ verdict: 'not_seen', hits_count: 0 });
    expect(resultOf('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toMatchObject({ verdict: 'not_searched', reason: 'File hashes are not indexed on this platform' });
  });

  it('should record a run without hits as inconclusive while a value was not searched, benign once every value was', async () => {
    const runOnce = async (searchedAll: boolean) => {
      const started = await queryAsAdminWithSuccess({ query: HUNT_RUN_START, variables: { id: indicatorHuntId } });
      const [run] = started.data?.huntRunStart ?? [];
      const dispatched = await queryAsAdminWithSuccess({ query: HUNT_RUN_READ, variables: { id: run.id } });
      const keys = (dispatched.data?.huntRun.ioc_results as { key: string }[]).map((result) => result.key);
      await reportAsConnector(run.id, { status: 'running' });
      const reported = keys.map((key, index) => ({ key, seen: false, searched: searchedAll || index > 0 }));
      const completed = await reportAsConnector(run.id, { status: 'completed', truncated: false, ioc_results: reported });
      return completed.data?.huntRunReport.verdict;
    };
    expect(await runOnce(false)).toEqual('inconclusive');
    expect(await runOnce(true)).toEqual('benign');
    // Keep the connector free for the other suites: runs of this hunt are no longer dispatched
    await patchAttribute(testContext, ADMIN_USER, indicatorHuntId, 'Hunt', { hunt_status: 'paused' });
  });

  it('should show the permissions a connector declares and record its connection test, check by check', async () => {
    const registration = await queryAsUserWithSuccess(USER_CONNECTOR, {
      query: gql`mutation HuntConnectorSetup($input: HuntConnectorRegisterInput!) {
        huntConnectorRegister(input: $input) { required_permissions { name purpose } documentation_url }
      }`,
      variables: {
        input: {
          connector_id: CONNECTOR_ID,
          platform: 'splunk',
          languages: ['spl'],
          security_platform_name: SECURITY_PLATFORM_NAME,
          supports_indicators: true,
          required_permissions: [{ name: 'search', purpose: 'Run the hunt searches' }, { name: ' ', purpose: 'Dropped: no name' }],
          documentation_url: 'http://not-https.example.com',
        },
      },
    });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    expect(registration.data?.huntConnectorRegister.required_permissions).toEqual([{ name: 'search', purpose: 'Run the hunt searches' }]);
    expect(registration.data?.huntConnectorRegister.documentation_url).toBeNull();
    const CHECK_READ = gql`query HuntConnectorCheck($id: String!) { connector(id: $id) { hunt { connection_check { id status checks { name ok message } } } } }`;
    const requested = await queryAsAdminWithSuccess({
      query: gql`mutation HuntConnectorTest($id: ID!) { huntConnectorTestConnection(id: $id) { connection_check { id status } } }`,
      variables: { id: CONNECTOR_ID },
    });
    const check = requested.data?.huntConnectorTestConnection.connection_check;
    expect(check.status).toEqual('pending');
    const CHECK_REPORT = gql`mutation HuntConnectorCheckReport($input: HuntConnectorCheckReportInput!) {
      huntConnectorCheckReport(input: $input) { connection_check { status } }
    }`;
    const checks = [
      { name: 'Authentication', ok: true, message: 'The token is valid' },
      { name: 'search', ok: false, message: 'Access denied: the account lacks the search capability' },
    ];
    const stale = await queryAsUser(USER_CONNECTOR, { query: CHECK_REPORT, variables: { input: { connector_id: CONNECTOR_ID, check_id: 'another-test', checks } } });
    expect(stale.errors?.[0].message).toContain('not the last one requested');
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    await queryAsUserWithSuccess(USER_CONNECTOR, { query: CHECK_REPORT, variables: { input: { connector_id: CONNECTOR_ID, check_id: check.id, checks } } });
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    const read = await queryAsAdminWithSuccess({ query: CHECK_READ, variables: { id: CONNECTOR_ID } });
    expect(read.data?.connector.hunt.connection_check.status).toEqual('failed');
    expect(read.data?.connector.hunt.connection_check.checks[1].message).toEqual('Access denied: the account lacks the search capability');
  });
});
