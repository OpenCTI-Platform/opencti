import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { act, screen, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import type { OperationDescriptor } from 'relay-runtime';
import type { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import testRender from '../../../../utils/tests/test-render';
import SecurityCoverage from './SecurityCoverage';
import { buildResultScopeVariables } from './securityCoverageResultScope';
import type { SecurityCoverage_securityCoverage$key } from './__generated__/SecurityCoverage_securityCoverage.graphql';

// Records each call of the dispose function useQueryLoader gives for the scoped query.
const { disposeScopedQuerySpy } = vi.hoisted(() => ({ disposeScopedQuerySpy: vi.fn() }));

// useFragment is the identity: the tests give the overview its fragment data directly, and re-render it with other
// results the way the page subscription would. The queries and the subscription of the overview stay real;
// useQueryLoader is the real one, its dispose function for the scoped query is only recorded.
vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  const { useCallback } = await import('react');
  const useQueryLoader: typeof actual.useQueryLoader = (query, initialQueryReference) => {
    const [queryRef, loadQuery, disposeQuery] = actual.useQueryLoader(query, initialQueryReference);
    const isScopedQuery = (query as { params?: { name?: string } }).params?.name === 'SecurityCoverageScopedQuery';
    const recordedDisposeQuery = useCallback(() => {
      if (isScopedQuery) disposeScopedQuerySpy();
      disposeQuery();
    }, [isScopedQuery, disposeQuery]);
    return [queryRef, loadQuery, recordedDisposeQuery];
  };
  return {
    ...actual,
    useFragment: (_fragment: unknown, data: unknown) => data,
    useQueryLoader,
  };
});

// The list widgets are light, but read their real fragment from the scoped query like the real ones: in the app, the
// page query has already written the coverage, so the scoped query itself never misses data and what holds the
// previous content on screen is a widget suspending on the fragment of a result whose data has not arrived yet.
const { scopedWidget } = vi.hoisted(() => ({
  scopedWidget: async (testId: string, fragmentModule: Promise<{ default: unknown }>) => {
    const { useFragment } = await vi.importActual<typeof import('react-relay')>('react-relay');
    const { default: fragment } = await fragmentModule;
    type WidgetData = { name?: string; totalCountPerEntityType?: ReadonlyArray<{ value?: number | null } | null> | null };
    type FragmentRef = { __fragments?: unknown; __fragmentOwner?: { variables: { fromId?: string[] } } };
    const Widget = ({ securityCoverage, isResultScoped }: { securityCoverage: WidgetData & FragmentRef; isResultScoped?: boolean }) => {
      // The coverage data is given as plain data (useFragment is the identity), a scoped result as a fragment ref.
      const owner = securityCoverage.__fragmentOwner;
      const scopedData = useFragment(fragment as Parameters<typeof useFragment>[0], owner ? securityCoverage as never : null) as WidgetData | null;
      const counts = scopedData?.totalCountPerEntityType?.map((distribution) => distribution?.value).join(',');
      return (
        <div data-testid={testId} data-scoped={String(isResultScoped)}>
          {owner ? `scoped:${owner.variables.fromId?.join(',')}` : `coverage:${securityCoverage.name}`}
          {counts !== undefined && <span data-testid={`${testId}-counts`}>{counts}</span>}
        </div>
      );
    };
    return { default: Widget };
  },
}));

vi.mock('./SecurityCoverageMainInfo', () => ({
  default: ({ selectedResultId }: { selectedResultId: string | null }) => (
    <div data-testid="main-info">{selectedResultId ?? 'all-results'}</div>
  ),
}));
vi.mock('./SecurityCoverageTestedEntitiesChart', () => scopedWidget(
  'tested-entities',
  import('./__generated__/SecurityCoverageTestedEntitiesChart_securityCoverage.graphql'),
));
vi.mock('./SecurityCoverageDetails', () => scopedWidget(
  'details',
  import('./__generated__/SecurityCoverageDetails_securityCoverage.graphql'),
));
vi.mock('./SecurityCoverageAttackPatterns', () => scopedWidget(
  'attack-patterns',
  import('./__generated__/SecurityCoverageAttackPatternsFragment.graphql'),
));
vi.mock('../../common/stix_domain_objects/StixDomainObjectOverview', () => ({ default: () => <div data-testid="overview" /> }));
vi.mock('../external_references/StixCoreObjectExternalReferences', () => ({ default: () => null }));
vi.mock('../../common/stix_core_objects/StixCoreObjectLatestHistory', () => ({ default: () => null }));
vi.mock('../notes/StixCoreObjectOrStixCoreRelationshipNotes', () => ({ default: () => null }));

const COVERAGE_ID = 'security-coverage-id';
const COVERAGE_NAME = 'Coverage of APT28';
const lyon = { id: 'scr-lyon', name: 'OAEV Lyon', external_uri: null };
const paris = { id: 'scr-paris', name: 'OAEV Paris', external_uri: null };

const buildData = (securityCoverageResults: unknown[]) => ({
  id: COVERAGE_ID,
  name: COVERAGE_NAME,
  results: securityCoverageResults,
} as unknown as SecurityCoverage_securityCoverage$key);

const SCOPED_QUERY = 'SecurityCoverageScopedQuery';
const SCOPED_SUBSCRIPTION = 'SecurityCoverageScopedSubscription';

const operationName = (operation: OperationDescriptor) => operation.request.node.params.name;

// Every operation the overview asked the environment for, resolved or not: the mock environment records the calls of
// these methods (executeSubscription is missing from its type).
type RecordedMethod = { mock: { calls: [{ operation: OperationDescriptor }][] } };
const executedOperations = (relayEnv: RelayMockEnvironment): OperationDescriptor[] => {
  const recorded = relayEnv as unknown as Record<'execute' | 'executeWithSource' | 'executeSubscription', RecordedMethod>;
  return [recorded.execute, recorded.executeWithSource, recorded.executeSubscription]
    .flatMap((method) => method.mock.calls.map(([{ operation }]) => operation));
};

const executedNamed = (relayEnv: RelayMockEnvironment, name: string) => executedOperations(relayEnv)
  .filter((operation) => operationName(operation) === name);

// Operations still running: a resolved query leaves the list, a disposed query or subscription too.
const pendingNamed = (relayEnv: RelayMockEnvironment, name: string) => relayEnv.mock.getAllOperations()
  .filter((operation) => operationName(operation) === name);

const resolveOperation = async (relayEnv: RelayMockEnvironment, operation: OperationDescriptor) => {
  await act(async () => {
    relayEnv.mock.resolve(operation, MockPayloadGenerator.generate(operation, {
      SecurityCoverage: () => ({ id: COVERAGE_ID, name: COVERAGE_NAME }),
      Distribution: () => ({ label: 'Vulnerability', value: 1 }),
    }));
  });
};

const resolvePendingScopedQuery = async (relayEnv: RelayMockEnvironment) => {
  const [scopedQuery] = pendingNamed(relayEnv, SCOPED_QUERY);
  await resolveOperation(relayEnv, scopedQuery);
};

const renderOverview = async (securityCoverageResults: unknown[] = [lyon, paris]) => {
  const rendered = testRender(<SecurityCoverage data={buildData(securityCoverageResults)} />);
  // What the page query (RootSecurityCoverageQuery) has written before the overview mounts: the root field the scoped
  // query reads, without the data of any result.
  rendered.relayEnv.commitUpdate((store) => {
    const coverage = store.create(COVERAGE_ID, 'SecurityCoverage');
    coverage.setValue(COVERAGE_ID, 'id');
    store.getRoot().setLinkedRecord(coverage, 'securityCoverage', { id: COVERAGE_ID });
  });
  // The overview waits for the kill chains; the matrix query goes to the (mocked) attack patterns widget.
  const [killChains] = pendingNamed(rendered.relayEnv, 'SecurityCoverageKillChainsQuery');
  await resolveOperation(rendered.relayEnv, killChains);
  await screen.findByTestId('main-info');
  return rendered;
};

const selector = () => screen.getByRole('combobox', { name: 'Security Coverage Result' });

const pick = async (user: ReturnType<typeof testRender>['user'], optionName: string) => {
  await user.click(selector());
  await user.click(within(screen.getByRole('listbox')).getByRole('option', { name: optionName }));
};

const expectContent = (mainInfo: string, widgets: string, isResultScoped: boolean) => {
  expect(screen.getByTestId('main-info')).toHaveTextContent(mainInfo);
  ['tested-entities', 'details', 'attack-patterns'].forEach((testId) => {
    const widget = screen.getByTestId(testId);
    expect(widget).toHaveTextContent(widgets);
    expect(widget).toHaveAttribute('data-scoped', String(isResultScoped));
  });
};

describe('Component: SecurityCoverage overview', () => {
  beforeEach(() => {
    disposeScopedQuerySpy.mockClear();
  });

  it('shows all results at first, from the coverage data, without any scoped query or subscription', async () => {
    const { relayEnv } = await renderOverview();

    expect(selector()).toHaveTextContent('Security Coverage Result');
    expectContent('all-results', `coverage:${COVERAGE_NAME}`, false);
    expect(executedNamed(relayEnv, SCOPED_QUERY)).toHaveLength(0);
    expect(executedNamed(relayEnv, SCOPED_SUBSCRIPTION)).toHaveLength(0);
  });

  it('moves the menu at once, and the content only once the scoped query of the picked result has answered', async () => {
    const { relayEnv, user } = await renderOverview();

    await pick(user, 'OAEV Paris');

    expect(selector()).toHaveTextContent('OAEV Paris');
    // On a first pick the query ref is still empty: only the next test proves the content follows the committed query, not the menu
    const scopedQueries = pendingNamed(relayEnv, SCOPED_QUERY);
    expect(scopedQueries).toHaveLength(1);
    expect(scopedQueries[0].request.variables).toEqual(buildResultScopeVariables(COVERAGE_ID, paris.id));
    // Not answered yet: the content stays on all results
    expectContent('all-results', `coverage:${COVERAGE_NAME}`, false);

    await resolvePendingScopedQuery(relayEnv);

    expectContent(paris.id, `scoped:${paris.id}`, true);
  });

  it('keeps the previous result on screen until the query of the next one has answered', async () => {
    const { relayEnv, user } = await renderOverview();
    await pick(user, 'OAEV Paris');
    await resolvePendingScopedQuery(relayEnv);

    await pick(user, 'OAEV Lyon');

    expect(selector()).toHaveTextContent('OAEV Lyon');
    expect(pendingNamed(relayEnv, SCOPED_QUERY)[0].request.variables).toEqual(buildResultScopeVariables(COVERAGE_ID, lyon.id));
    expectContent(paris.id, `scoped:${paris.id}`, true);

    await resolvePendingScopedQuery(relayEnv);

    expectContent(lyon.id, `scoped:${lyon.id}`, true);
  });

  it('goes back to the coverage data when all results is picked again', async () => {
    const { relayEnv, user } = await renderOverview();
    await pick(user, 'OAEV Paris');
    await resolvePendingScopedQuery(relayEnv);
    expect(disposeScopedQuerySpy).not.toHaveBeenCalled();

    await pick(user, 'All results');

    expect(disposeScopedQuerySpy).toHaveBeenCalledTimes(1);
    expect(selector()).toHaveTextContent('Security Coverage Result');
    expectContent('all-results', `coverage:${COVERAGE_NAME}`, false);
    // "All results" is no filter: nothing more is asked
    expect(executedNamed(relayEnv, SCOPED_QUERY)).toHaveLength(1);
  });

  it('drops a result picked and left before its query has answered: its late answer does not take over', async () => {
    const { relayEnv, user } = await renderOverview();
    await pick(user, 'OAEV Paris');

    await pick(user, 'All results');
    expectContent('all-results', `coverage:${COVERAGE_NAME}`, false);
    // The suspended render that read the request keeps it alive (until Relay releases it), so the late answer really reaches the store
    const lateQueries = pendingNamed(relayEnv, SCOPED_QUERY);
    expect(lateQueries).toHaveLength(1);
    expect(lateQueries[0].request.variables).toEqual(buildResultScopeVariables(COVERAGE_ID, paris.id));
    await resolveOperation(relayEnv, lateQueries[0]);

    expect(selector()).toHaveTextContent('Security Coverage Result');
    expectContent('all-results', `coverage:${COVERAGE_NAME}`, false);
    expect(executedNamed(relayEnv, SCOPED_SUBSCRIPTION)).toHaveLength(0);
  });

  it('falls back to all results when the selected result leaves the coverage', async () => {
    const { relayEnv, user, rerender } = await renderOverview();
    await pick(user, 'OAEV Paris');
    await resolvePendingScopedQuery(relayEnv);
    expectContent(paris.id, `scoped:${paris.id}`, true);
    expect(disposeScopedQuerySpy).not.toHaveBeenCalled();

    // The coverage is pushed again without the selected result (deleted, or no longer visible to the user)
    await act(async () => {
      rerender(<SecurityCoverage data={buildData([lyon])} />);
    });

    expect(disposeScopedQuerySpy).toHaveBeenCalledTimes(1);

    expect(selector()).toHaveTextContent('Security Coverage Result');
    expectContent('all-results', `coverage:${COVERAGE_NAME}`, false);
    expect(pendingNamed(relayEnv, SCOPED_SUBSCRIPTION)).toHaveLength(0);
  });

  it('subscribes to the scoped widgets only while a result is displayed, with the variables of the scoped query', async () => {
    const { relayEnv, user } = await renderOverview();

    await pick(user, 'OAEV Paris');
    // Picked but not displayed yet: no subscription
    expect(executedNamed(relayEnv, SCOPED_SUBSCRIPTION)).toHaveLength(0);

    await resolvePendingScopedQuery(relayEnv);

    const subscriptions = pendingNamed(relayEnv, SCOPED_SUBSCRIPTION);
    expect(subscriptions).toHaveLength(1);
    expect(subscriptions[0].request.variables).toEqual(buildResultScopeVariables(COVERAGE_ID, paris.id));

    await pick(user, 'All results');

    expect(pendingNamed(relayEnv, SCOPED_SUBSCRIPTION)).toHaveLength(0);
    expect(executedNamed(relayEnv, SCOPED_SUBSCRIPTION)).toHaveLength(1);
  });

  it('updates the scoped widgets live when the subscription pushes the displayed result', async () => {
    const { relayEnv, user } = await renderOverview();
    await pick(user, 'OAEV Paris');
    await resolvePendingScopedQuery(relayEnv);
    expect(screen.getByTestId('tested-entities-counts')).toHaveTextContent(/^1(,1)*$/);
    const [subscription] = pendingNamed(relayEnv, SCOPED_SUBSCRIPTION);

    // e.g. OpenAEV upserts the coverage with new results: the event carries the entities of the displayed result
    await act(async () => {
      relayEnv.mock.nextValue(subscription, MockPayloadGenerator.generate(subscription, {
        SecurityCoverage: () => ({ id: COVERAGE_ID, name: COVERAGE_NAME }),
        Distribution: () => ({ label: 'Vulnerability', value: 7 }),
      }));
    });

    // Written under the keys of the scoped query (same arguments), so the widget reading them re-renders
    expect(screen.getByTestId('tested-entities-counts')).toHaveTextContent(/^7(,7)*$/);
    expectContent(paris.id, `scoped:${paris.id}`, true);
  });
});
