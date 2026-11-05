import React from 'react';
import { act } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import { graphSelectionActionsFor } from '../../../../../components/graph/badges';
import { graphNode } from '../../../../../utils/tests/graphTestData';
import InvestigationEnrichmentMenuAction, { INVESTIGATION_ENRICHMENT_MENU_ACTION_ID } from './InvestigationEnrichmentMenuAction';

const ip = graphNode({ id: 'ip-1', label: '198.51.100.7', entity_type: 'IPv4-Addr' });
const otherIp = graphNode({ id: 'ip-2', label: '203.0.113.24', entity_type: 'IPv4-Addr' });
const domain = graphNode({ id: 'domain-1', label: 'example.com', entity_type: 'Domain-Name' });

const mocks = vi.hoisted(() => ({
  backgroundTaskLaunch: vi.fn(),
  fetchQuery: vi.fn(),
  selectedNodes: [] as unknown[],
}));

vi.mock('../../../common/background_task/BackgroundTaskLaunch', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.backgroundTaskLaunch(props);
    return null;
  },
}));

vi.mock('../../../../../relay/environment', () => ({
  fetchQuery: mocks.fetchQuery,
}));

vi.mock('../../../../../components/graph/GraphContext', () => ({
  useGraphContext: () => ({
    graphState: { selectedNodes: mocks.selectedNodes, selectedLinks: [] },
  }),
}));

const t_i18n = (message: string) => message;

/**
 * Makes the next connector queries answer with these connectors once `resolve` is called, or fail
 * once `reject` is called.
 */
const answerConnectors = () => {
  let resolve: (names: string[]) => void = () => {};
  let reject: () => void = () => {};
  mocks.fetchQuery.mockReturnValue({
    toPromise: () => new Promise((done, fail) => {
      resolve = (names) => done({ enrichmentConnectors: names.map((name, i) => ({ id: `connector-${i + 1}`, name })) });
      reject = () => fail(new Error('network'));
    }),
  });
  return {
    resolve: (names: string[]) => act(async () => resolve(names)),
    reject: () => act(async () => reject()),
  };
};

/**
 * The Enrichment action as the context menu of the investigation graph sees it, if registered.
 */
const enrichmentAction = () => {
  const selection = { nodes: [], links: [] };
  const action = graphSelectionActionsFor(selection, 'investigation').find((a) => a.id === INVESTIGATION_ENRICHMENT_MENU_ACTION_ID);
  return action && {
    label: action.label(t_i18n),
    disabledReason: action.disabledReason?.(selection, t_i18n),
    options: action.options?.(selection, t_i18n),
  };
};

/**
 * Returns the props given to the background task launcher on its last render.
 */
const lastLaunchProps = () => {
  const { calls } = mocks.backgroundTaskLaunch.mock;
  return calls[calls.length - 1][0];
};

const renderAction = (canLaunch = true, onLaunched = () => {}) => testRender(
  <InvestigationEnrichmentMenuAction investigationId="investigation-1" canLaunch={canLaunch} onLaunched={onLaunched} />,
);

describe('InvestigationEnrichmentMenuAction', () => {
  let view: ReturnType<typeof renderAction> | undefined;
  afterEach(() => {
    view?.unmount();
    view = undefined;
    mocks.fetchQuery.mockReset();
    mocks.backgroundTaskLaunch.mockReset();
  });

  it('is not in the menu for a user who cannot launch an enrichment', () => {
    mocks.selectedNodes = [ip];
    answerConnectors();
    view = renderAction(false);
    expect(enrichmentAction()).toBeUndefined();
    expect(mocks.fetchQuery).not.toHaveBeenCalled();
  });

  it('is only in the menu of the investigation graph', () => {
    mocks.selectedNodes = [ip];
    answerConnectors();
    view = renderAction();
    const registeredIds = (context: string | undefined) => graphSelectionActionsFor({ nodes: [], links: [] }, context).map((a) => a.id);
    expect(registeredIds('investigation')).toContain(INVESTIGATION_ENRICHMENT_MENU_ACTION_ID);
    expect(registeredIds(undefined)).not.toContain(INVESTIGATION_ENRICHMENT_MENU_ACTION_ID);
    expect(registeredIds('correlation')).not.toContain(INVESTIGATION_ENRICHMENT_MENU_ACTION_ID);
  });

  it('is disabled while the connectors of the selection load, then lists them', async () => {
    mocks.selectedNodes = [ip, otherIp];
    const query = answerConnectors();
    view = renderAction();
    expect(enrichmentAction()?.label).toBe('Enrichment');
    expect(enrichmentAction()?.disabledReason).toBe('Loading');
    expect(mocks.fetchQuery).toHaveBeenCalledWith(expect.anything(), { type: 'IPv4-Addr' });

    await query.resolve(['Coucou Enrichment', 'Shodan']);

    expect(enrichmentAction()?.disabledReason).toBeUndefined();
    expect(enrichmentAction()?.options?.items).toEqual([
      { key: 'connector-1', label: 'Coucou Enrichment' },
      { key: 'connector-2', label: 'Shodan' },
    ]);
  });

  it('is disabled with the drawer message for a selection mixing types, without loading connectors', () => {
    mocks.selectedNodes = [ip, domain];
    answerConnectors();
    view = renderAction();
    expect(enrichmentAction()?.disabledReason).toBe('No connector available for the selected entities.');
    expect(mocks.fetchQuery).not.toHaveBeenCalled();
  });

  it('is disabled with the drawer message when no connector enriches the type', async () => {
    mocks.selectedNodes = [domain];
    const query = answerConnectors();
    view = renderAction();
    await query.resolve([]);
    expect(enrichmentAction()?.disabledReason).toBe('No connector available for the selected entities.');
  });

  it('is disabled with the drawer message when the connectors cannot be loaded', async () => {
    mocks.selectedNodes = [ip];
    const query = answerConnectors();
    view = renderAction();
    await query.reject();
    expect(enrichmentAction()?.disabledReason).toBe('No connector available for the selected entities.');
  });

  it('ignores the connectors of a type no longer selected when they arrive late', async () => {
    mocks.selectedNodes = [ip];
    const ipQuery = answerConnectors();
    view = renderAction();
    mocks.selectedNodes = [domain];
    const domainQuery = answerConnectors();
    view.rerender(<InvestigationEnrichmentMenuAction investigationId="investigation-1" canLaunch onLaunched={() => {}} />);

    await domainQuery.resolve(['DomainTools']);
    await ipQuery.resolve(['Coucou Enrichment']);

    expect(enrichmentAction()?.disabledReason).toBeUndefined();
    expect(enrichmentAction()?.options?.items).toEqual([{ key: 'connector-1', label: 'DomainTools' }]);
  });

  it('opens the launcher with the connector picked only, and launches nothing on cancel', async () => {
    mocks.selectedNodes = [ip, otherIp];
    const query = answerConnectors();
    const onLaunched = vi.fn();
    view = renderAction(true, onLaunched);
    await query.resolve(['Coucou Enrichment', 'Shodan']);
    expect(lastLaunchProps().display).toBe(false);

    act(() => enrichmentAction()?.options?.onSelect('connector-2'));

    expect(lastLaunchProps()).toMatchObject({
      display: true,
      numberOfSelectedElements: 2,
      actions: [{ type: 'ENRICHMENT', context: { values: ['connector-2'], options: { investigationId: 'investigation-1' } } }],
    });
    expect(Object.keys(lastLaunchProps().selectedElements)).toEqual(['ip-1', 'ip-2']);

    act(() => lastLaunchProps().onClose());

    expect(lastLaunchProps().display).toBe(false);
    expect(onLaunched).not.toHaveBeenCalled();
  });

  it('is not left busy for the next enrichment when a launch the API rejected is closed', async () => {
    mocks.selectedNodes = [ip];
    const query = answerConnectors();
    const onLaunched = vi.fn();
    view = renderAction(true, onLaunched);
    await query.resolve(['Coucou Enrichment']);
    act(() => enrichmentAction()?.options?.onSelect('connector-1'));
    act(() => lastLaunchProps().onLaunch());

    // The mutation failed: onCompleted never comes, the user closes the launcher.
    act(() => lastLaunchProps().onClose());
    act(() => enrichmentAction()?.options?.onSelect('connector-1'));

    expect(lastLaunchProps()).toMatchObject({ display: true, processing: false });
    expect(onLaunched).not.toHaveBeenCalled();
  });

  it('closes the launcher and hands over once the enrichment is launched', async () => {
    mocks.selectedNodes = [ip];
    const query = answerConnectors();
    const onLaunched = vi.fn();
    view = renderAction(true, onLaunched);
    await query.resolve(['Coucou Enrichment']);
    act(() => enrichmentAction()?.options?.onSelect('connector-1'));

    act(() => lastLaunchProps().onLaunch());
    expect(lastLaunchProps().processing).toBe(true);
    act(() => lastLaunchProps().onCompleted());

    expect(lastLaunchProps()).toMatchObject({ display: false, processing: false });
    expect(onLaunched).toHaveBeenCalledTimes(1);
  });
});
