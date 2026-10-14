import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { OperationDescriptor } from 'relay-runtime';
import useShouldCoverOverlap from '@components/common/stix_domain_objects/useShouldCoverOverlap';
import testRender from '../../../../../utils/tests/test-render';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { GraphState } from '../../../../../components/graph/graph.types';
import { commitMutation } from 'react-relay';
import { MESSAGING$ } from '../../../../../relay/environment';
import { INVESTIGATION_MATRIX_EXPORT_ID } from '../InvestigationViewSwitcher';
import InvestigationMatrix from './InvestigationMatrix';

vi.mock('../../../../../utils/hooks/useTopBanner', () => ({ default: () => ({ height: 0 }) }));
vi.mock('../../../../../components/graph/GraphContext', () => ({ useGraphContext: vi.fn() }));
vi.mock('@components/common/stix_domain_objects/useShouldCoverOverlap', () => ({ default: vi.fn() }));
vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  commitMutation: vi.fn(),
}));

const PLACED_ID = 'attack-pattern--placed';
const REVOKED_ID = 'attack-pattern--revoked';

const technique = (id: string, name: string, x_mitre_id: string, subAttackPatterns: unknown[] = []) => ({
  attack_pattern_id: id,
  name,
  description: null,
  x_mitre_id,
  subAttackPatterns,
  subAttackPatternsSearchText: null,
  killChainPhasesIds: [],
});

const phase = (kill_chain_name: string, phase_name: string, attackPatterns: unknown[]) => ({
  kill_chain_id: `${kill_chain_name}--${phase_name}`,
  kill_chain_name,
  phase_name,
  x_opencti_order: 1,
  attackPatterns,
});

const MITRE_PHASES = [phase('mitre-attack', 'execution', [technique(PLACED_ID, 'Placed', 'T1001')])];
const PARENT_ID = 'attack-pattern--parent';
const SUB_ID = 'attack-pattern--sub';
const SUB = { attack_pattern_id: SUB_ID, name: 'Sub', description: null, x_mitre_id: 'T1002.001' };
const HEAT_PHASES = [phase('mitre-attack', 'execution', [
  technique(PLACED_ID, 'Placed', 'T1001'),
  technique(PARENT_ID, 'Parent', 'T1002', [SUB]),
])];
// No mitre-attack: the select must default to the first kill chain alphabetically.
const OTHER_PHASES = [
  phase('zeta-chain', 'zeta-phase', [technique('attack-pattern--zeta', 'Zeta', 'T2001')]),
  phase('alpha-chain', 'alpha-phase', [technique(PLACED_ID, 'Placed', 'T1001')]),
];

const resolver = (phases: unknown[]) => (operation: OperationDescriptor) => MockPayloadGenerator.generate(operation, {
  AttackPatternsMatrix: () => ({ attackPatternsOfPhases: phases }),
});

const attackPattern = (id: string, name: string) => ({ id, entity_type: 'Attack-Pattern', name, parent_types: ['Stix-Domain-Object'] });
const intrusionSet = (id: string, name: string) => ({ id, entity_type: 'Intrusion-Set', name, parent_types: ['Stix-Domain-Object'] });
const uses = (id: string, fromId: string, toId: string) => ({
  id,
  entity_type: 'stix-core-relationship',
  relationship_type: 'uses',
  parent_types: ['basic-relationship', 'stix-core-relationship'],
  from: { id: fromId },
  to: { id: toId },
});
// T1001 is used by two intrusion sets (score 2), its neighbour's sub-technique by one (score 1).
const SCORED_OBJECTS = [
  attackPattern(PLACED_ID, 'Placed'),
  attackPattern(SUB_ID, 'Sub'),
  intrusionSet('is-a', 'APT A'),
  intrusionSet('is-b', 'APT B'),
  uses('rel-1', 'is-a', PLACED_ID),
  uses('rel-2', 'is-b', PLACED_ID),
  uses('rel-3', 'is-a', SUB_ID),
];
const HEATMAP_LABEL = 'Displays heat map of attack pattern use';
const NO_SCORE_LABEL = 'No attack pattern is linked to an entity in this investigation';
const heatmapToggle = () => screen.getByRole('button', { name: HEATMAP_LABEL });
const heatmapEnabledCalls = () => vi.mocked(commitMutation).mock.calls
  .filter(([, config]) => config.variables.event === 'HEATMAP_ENABLED');

const DEFAULT_GRAPH_STATE: Partial<GraphState> = {
  loadingCurrent: 2,
  loadingTotal: 2,
  disabledEntityTypes: [],
  disabledCreators: [],
  disabledMarkings: [],
  selectedTimeRangeInterval: undefined,
};

const POSTURE_ERROR = new Error('posture lookup failed');

interface RenderOptions {
  rawObjects?: unknown[];
  graphState?: Partial<GraphState>;
  phases?: unknown[];
  postureError?: Error | null;
}

const renderMatrix = async ({
  rawObjects = [attackPattern(PLACED_ID, 'Placed')],
  graphState = {},
  phases = MITRE_PHASES,
  postureError = null,
}: RenderOptions = {}) => {
  vi.mocked(useGraphContext).mockReturnValue({
    rawObjects,
    graphState: { ...DEFAULT_GRAPH_STATE, ...graphState },
  } as unknown as ReturnType<typeof useGraphContext>);
  vi.mocked(useShouldCoverOverlap).mockReturnValue({
    attackPatternIdsToOverlap: undefined,
    setSecurityPlatformIds: vi.fn(),
    error: postureError,
  });
  const ui = <InvestigationMatrix investigationId="investigation-1" />;
  const rendered = testRender(ui);
  const { mock } = rendered.relayEnv;
  // Queries are issued in effects, some only once an earlier one has answered (the posture
  // select mounts after the matrix query): answer every pending one until none is left.
  for (let round = 0; round < 5 && mock.getAllOperations().length > 0; round += 1) {
    await act(async () => {
      mock.getAllOperations().forEach((operation) => mock.resolve(operation, resolver(phases)(operation)));
    });
  }
  return { ...rendered, ui };
};

describe('InvestigationMatrix', () => {
  let notifyError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.mocked(commitMutation).mockClear();
    notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
  });

  afterEach(() => {
    notifyError.mockRestore();
  });

  it('sends the matrix usage event once per mount, even while the investigation is loading', async () => {
    const { unmount } = await renderMatrix({ graphState: { loadingCurrent: 0, loadingTotal: 1000 } });
    expect(commitMutation).toHaveBeenCalledTimes(1);
    expect(vi.mocked(commitMutation).mock.calls[0][1].variables).toEqual({ id: 'investigation-1', event: 'MATRIX_VIEWED' });
    unmount();
    await renderMatrix();
    expect(commitMutation).toHaveBeenCalledTimes(2);
  });

  it('shows the graph progress and no matrix while the investigation is loading', async () => {
    await renderMatrix({ graphState: { loadingCurrent: 200, loadingTotal: 1000 } });
    expect(await screen.findByText('200 / 1000')).toBeInTheDocument();
    expect(document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID)).toBeNull();
  });

  it('keeps the progress visible before the first page is counted', async () => {
    await renderMatrix({ graphState: { loadingCurrent: 0, loadingTotal: 1000 } });
    expect(screen.getByRole('status')).toHaveTextContent('0 / 1000');
    expect(document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID)).toBeNull();
    expect(screen.queryByText('Add attack patterns to the graph view to visualise them here')).toBeNull();
  });

  it('shows the empty text when the investigation has no attack pattern', async () => {
    await renderMatrix({ rawObjects: [{ id: 'is-1', entity_type: 'Intrusion-Set', name: 'APT', parent_types: [] }] });
    expect(await screen.findByText('Add attack patterns to the graph view to visualise them here')).toBeInTheDocument();
    expect(screen.queryByText('T1001 - Placed')).toBeNull();
    expect(screen.getByRole('button', { name: 'Display only used techniques' })).toBeDisabled();
    expect(screen.getByRole('combobox', { name: 'Kill chain :' })).toBeDisabled();
    expect(await screen.findByRole('combobox', { name: 'Compare with my security posture' })).toBeDisabled();
  });

  it('notes the attack patterns that cannot be placed in the kill chain', async () => {
    await renderMatrix({ rawObjects: [attackPattern(PLACED_ID, 'Placed'), attackPattern(REVOKED_ID, 'Revoked')] });
    expect(await screen.findByText('1 attack pattern in this investigation isn\'t shown in this kill chain')).toBeInTheDocument();
    expect(screen.getByText('T1001 - Placed')).toBeInTheDocument();
  });

  it('uses the plural when several attack patterns cannot be placed', async () => {
    await renderMatrix({
      rawObjects: [
        attackPattern(PLACED_ID, 'Placed'),
        attackPattern(REVOKED_ID, 'Revoked'),
        attackPattern('attack-pattern--other', 'Other'),
      ],
    });
    expect(await screen.findByText('2 attack patterns in this investigation aren\'t shown in this kill chain')).toBeInTheDocument();
  });

  it('notes that graph filters do not apply to the matrix', async () => {
    await renderMatrix({ graphState: { disabledEntityTypes: ['Report'] } });
    expect(await screen.findByText('Graph filters don\'t apply to the matrix')).toBeInTheDocument();
  });

  it('defaults to the first kill chain alphabetically without mitre-attack and renders its columns', async () => {
    await renderMatrix({ phases: OTHER_PHASES });
    expect(await screen.findByText('T1001 - Placed')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Kill chain :' })).toHaveTextContent('alpha-chain');
    expect(screen.getByText('alpha-phase')).toBeInTheDocument();
    expect(screen.queryByText('zeta-phase')).toBeNull();
  });

  it('wraps toolbar, notes and matrix in the export element, with no export button', async () => {
    await renderMatrix();
    await screen.findByText('T1001 - Placed');
    const wrapper = document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID);
    expect(wrapper).not.toBeNull();
    expect(wrapper).toContainElement(screen.getByRole('combobox', { name: 'Kill chain :' }));
    expect(wrapper).toContainElement(screen.getByText('T1001 - Placed'));
    expect(screen.queryByRole('button', { name: /export/i })).toBeNull();
  });

  describe('heatmap', () => {
    it('places the toggle between "only used" and the posture, with its tooltip', async () => {
      const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      const onlyUsed = screen.getByRole('button', { name: 'Display only used techniques' });
      const posture = await screen.findByRole('combobox', { name: 'Compare with my security posture' });
      expect(onlyUsed.compareDocumentPosition(heatmapToggle()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(heatmapToggle().compareDocumentPosition(posture) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(heatmapToggle()).toBeEnabled();
      await user.hover(heatmapToggle());
      expect(await screen.findByRole('tooltip')).toHaveTextContent(HEATMAP_LABEL);
    });

    it('disables the toggle without scores and explains why on focus of its wrapper', async () => {
      const { user } = await renderMatrix();
      await screen.findByText('T1001 - Placed');
      expect(heatmapToggle()).toBeDisabled();
      const wrapper = heatmapToggle().parentElement as HTMLElement;
      expect(wrapper.tagName).toBe('SPAN');
      expect(wrapper).toHaveAttribute('tabindex', '0');
      while (document.activeElement !== wrapper) await user.tab();
      expect(await screen.findByRole('tooltip')).toHaveTextContent(NO_SCORE_LABEL);
    });

    it('disables the toggle in the empty state', async () => {
      await renderMatrix({ rawObjects: [intrusionSet('is-a', 'APT A')] });
      await screen.findByText('Add attack patterns to the graph view to visualise them here');
      expect(heatmapToggle()).toBeDisabled();
    });

    it('shows the legend and sends HEATMAP_ENABLED on each off-to-on switch', async () => {
      const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();
      expect(heatmapEnabledCalls()).toHaveLength(0);

      await user.click(heatmapToggle());
      const legend = screen.getByRole('img', { name: 'Technique usage scale, 1 to 2' });
      expect(document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID)).toContainElement(legend);
      expect(heatmapEnabledCalls()).toHaveLength(1);
      expect(heatmapEnabledCalls()[0][1].variables).toEqual({ id: 'investigation-1', event: 'HEATMAP_ENABLED' });

      await user.click(heatmapToggle());
      expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();
      expect(heatmapEnabledCalls()).toHaveLength(1);

      await user.click(heatmapToggle());
      expect(screen.getByRole('img', { name: 'Technique usage scale, 1 to 2' })).toBeInTheDocument();
      expect(heatmapEnabledCalls()).toHaveLength(2);
    });

    it('names scored cells after their linked entities', async () => {
      await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 2 entities' })).toBeInTheDocument();
    });

    it('keeps the sub-technique accordions collapsed with the heatmap on', async () => {
      const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      await user.click(heatmapToggle());
      const parent = screen.getByRole('button', { name: 'T1002 - Parent, linked to 1 entity' });
      expect(within(parent).getByRole('button', { name: 'Expand' })).toHaveAttribute('aria-expanded', 'false');
      expect(screen.queryByText('T1002.001 - Sub')).toBeNull();
    });
  });

  it('notifies a failed posture lookup once and still renders the matrix', async () => {
    const { rerender, ui } = await renderMatrix({ postureError: POSTURE_ERROR });
    expect(await screen.findByText('T1001 - Placed')).toBeInTheDocument();
    rerender(ui);
    expect(notifyError).toHaveBeenCalledTimes(1);
  });
});
