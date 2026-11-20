import React, { useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import type { UserEvent } from '@testing-library/user-event';
import { MockPayloadGenerator } from 'relay-test-utils';
import { OperationDescriptor } from 'relay-runtime';
import useShouldCoverOverlap from '@components/common/stix_domain_objects/useShouldCoverOverlap';
import testRender from '../../../../../utils/tests/test-render';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { GraphState } from '../../../../../components/graph/graph.types';
import { MESSAGING$ } from '../../../../../relay/environment';
import { INVESTIGATION_MATRIX_EXPORT_ID } from '../InvestigationViewSwitcher';
import InvestigationMatrix from './InvestigationMatrix';
import { DEFAULT_INVESTIGATION_MATRIX_SETTINGS, InvestigationMatrixSettings, matrixFiltersStorageKey, useInvestigationMatrixFilters } from './investigationMatrixSettings';
import type { GraphToolbarTimeRangeProps } from '../../../../../components/graph/components/GraphToolbarTimeRange';
import { GRAPH_TOOLBAR_HEIGHT, GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE } from '../../../../../components/graph/utils/graphFraming';

vi.mock('../../../../../utils/hooks/useTopBanner', () => ({ default: () => ({ height: 0 }) }));
vi.mock('../../../../../components/graph/GraphContext', () => ({ useGraphContext: vi.fn() }));
vi.mock('@components/common/stix_domain_objects/useShouldCoverOverlap', () => ({ default: vi.fn() }));

// jsdom cannot drag the range slider: a stand-in moves the range as a drag would, and shows what the panel is given.
// The real panel is drawn where what it does on its own matters (the slider snaps its values when it mounts).
const JANUARY: [Date, Date] = [new Date('2026-01-01T00:00:00.000Z'), new Date('2026-02-01T00:00:00.000Z')];
const timeRangePanel = vi.hoisted(() => ({ real: false }));
vi.mock('../../../../../components/graph/components/GraphToolbarTimeRange', async (importOriginal) => {
  const { default: RealTimeRange } = await importOriginal<typeof import('../../../../../components/graph/components/GraphToolbarTimeRange')>();
  return {
    default: (props: GraphToolbarTimeRangeProps) => (timeRangePanel.real ? <RealTimeRange {...props} /> : <TimeRangeStandIn {...props} />),
  };
});
// jsdom gives the responsive chart no size: a plain box stands for it.
vi.mock('recharts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('recharts')>()),
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
const TimeRangeStandIn = ({ timeRange, selectedInterval, onChange }: GraphToolbarTimeRangeProps) => (
  <div role="region" aria-label="Time range panel (test)">
    <span>{`Dated links: ${timeRange.values.reduce((sum, { value }) => sum + value, 0)}`}</span>
    <span>{`Selected: ${selectedInterval ? selectedInterval.map((date) => date.toISOString()).join(' to ') : 'whole range'}`}</span>
    <button type="button" onClick={() => onChange(JANUARY)}>Keep January (test)</button>
    <button type="button" onClick={() => onChange(timeRange.interval)}>Keep the whole range (test)</button>
  </div>
);

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
const MALWARE_ID = 'malware--emotet';
const GREEN = { id: 'marking--green', definition: 'TLP:GREEN' };
const ACME = { id: 'identity--acme', name: 'ACME' };
const malware = (id: string, name: string) => ({ id, entity_type: 'Malware', name, parent_types: ['Stix-Domain-Object'] });
const dated = <T extends object>(relationship: T, start_time: string, extra: object = {}) => ({ ...relationship, start_time, ...extra });
// T1001 is used by two intrusion sets (score 2): one by ACME, through a link marked TLP:GREEN. The sub-technique by a malware (score 1).
const FILTER_OBJECTS = [
  attackPattern(PLACED_ID, 'Placed'),
  attackPattern(SUB_ID, 'Sub'),
  { ...intrusionSet('is-a', 'APT A'), createdBy: ACME },
  intrusionSet('is-b', 'APT B'),
  malware(MALWARE_ID, 'Emotet'),
  dated(uses('rel-1', 'is-a', PLACED_ID), '2026-01-10T00:00:00.000Z', { objectMarking: [GREEN] }),
  dated(uses('rel-2', 'is-b', PLACED_ID), '2026-03-10T00:00:00.000Z'),
  dated(uses('rel-3', MALWARE_ID, SUB_ID), '2026-01-20T00:00:00.000Z'),
];
const HEATMAP_LABEL = 'Displays heat map of attack pattern use';
const NO_FILTERED_SCORE_LABEL = 'No attack pattern is left linked to an entity with these filters';
const INVESTIGATION_ID = 'investigation--test';
const NO_SCORE_LABEL = 'No attack pattern is linked to an entity in this investigation';
const matrixToolbar = () => screen.getByRole('toolbar', { name: 'Matrix toolbar' });
const heatmapToggle = () => within(matrixToolbar()).getByRole('button', { name: HEATMAP_LABEL });

const DEFAULT_GRAPH_STATE: Partial<GraphState> = {
  loadingCurrent: 2,
  loadingTotal: 2,
};

const POSTURE_ERROR = new Error('posture lookup failed');

interface RenderOptions {
  rawObjects?: unknown[];
  graphState?: Partial<GraphState>;
  phases?: unknown[];
  postureError?: Error | null;
}

const setGraphState = vi.fn();

const renderMatrix = async ({
  rawObjects = [attackPattern(PLACED_ID, 'Placed')],
  graphState = {},
  phases = MITRE_PHASES,
  postureError = null,
}: RenderOptions = {}) => {
  vi.mocked(useGraphContext).mockReturnValue({
    rawObjects,
    graphState: { ...DEFAULT_GRAPH_STATE, ...graphState },
    setGraphState,
  } as unknown as ReturnType<typeof useGraphContext>);
  vi.mocked(useShouldCoverOverlap).mockReturnValue({
    attackPatternIdsToOverlap: undefined,
    setSecurityPlatformIds: vi.fn(),
    error: postureError,
  });
  const ui = <MatrixWithSettings />;
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

// Stands in for the investigation graph: it holds the matrix settings and filters, and unmounts the matrix on a view switch.
const MatrixWithSettings = () => {
  const [settings, setSettings] = useState<InvestigationMatrixSettings>(DEFAULT_INVESTIGATION_MATRIX_SETTINGS);
  const [filters, changeFilters, clearFilters] = useInvestigationMatrixFilters(INVESTIGATION_ID);
  const [isMatrixShown, setIsMatrixShown] = useState(true);
  return (
    <>
      <button type="button" onClick={() => setIsMatrixShown((shown) => !shown)}>Switch view (test)</button>
      {isMatrixShown && (
        <InvestigationMatrix
          settings={settings}
          onSettingsChange={(change) => setSettings((current) => ({ ...current, ...change }))}
          filters={filters}
          onFiltersChange={changeFilters}
          onFiltersClear={clearFilters}
          exportName="Investigation - Matrix view"
        />
      )}
    </>
  );
};

describe('InvestigationMatrix', () => {
  let notifyError: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
  });

  afterEach(() => {
    notifyError.mockRestore();
    setGraphState.mockClear();
    localStorage.clear();
    timeRangePanel.real = false;
    // The console spy of a test.
    vi.restoreAllMocks();
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
    expect(screen.getByRole('button', { name: 'Display only used techniques' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByRole('combobox', { name: 'Kill chain' })).toBeDisabled();
    expect(await screen.findByRole('combobox', { name: 'Compare with my security posture' })).toBeDisabled();
  });

  it('notes the attack patterns that cannot be placed in the kill chain, in the toolbar', async () => {
    await renderMatrix({ rawObjects: [attackPattern(PLACED_ID, 'Placed'), attackPattern(REVOKED_ID, 'Revoked')] });
    expect(await within(matrixToolbar()).findByText('1 attack pattern not shown')).toBeInTheDocument();
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
    expect(await screen.findByText('2 attack patterns not shown')).toBeInTheDocument();
  });

  it('defaults to the first kill chain alphabetically without mitre-attack and renders its columns', async () => {
    await renderMatrix({ phases: OTHER_PHASES });
    expect(await screen.findByText('T1001 - Placed')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Kill chain' })).toHaveTextContent('alpha-chain');
    expect(screen.getByText('alpha-phase')).toBeInTheDocument();
    expect(screen.queryByText('zeta-phase')).toBeNull();
  });

  it('keeps the toolbar out of the export element and puts the legend in it, hidden on screen', async () => {
    const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
    await screen.findByText('T1001 - Placed');
    const wrapper = document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID) as HTMLElement;
    expect(wrapper).toContainElement(screen.getByText('T1001 - Placed'));
    expect(wrapper).not.toContainElement(matrixToolbar());

    await user.click(heatmapToggle());
    const exportLegend = within(wrapper).getByRole('img', { name: 'Technique usage scale, 1 to 2', hidden: true });
    expect(exportLegend.closest('[data-matrix-export-only]')).toHaveAttribute('hidden');
    // The legend seen on screen is the toolbar's.
    expect(screen.getByRole('img', { name: 'Technique usage scale, 1 to 2' })).not.toBe(exportLegend);
  });

  it('leaves no legend room in the export while the heatmap is off', async () => {
    const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
    await screen.findByText('T1001 - Placed');
    const wrapper = document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID) as HTMLElement;
    // The capture shows every export-only node: an empty one would still draw its margin in the image and the PDF.
    expect(wrapper.querySelector('[data-matrix-export-only]')).toBeNull();

    await user.click(heatmapToggle());
    expect(wrapper.querySelector('[data-matrix-export-only]')).not.toBeNull();
    await user.click(heatmapToggle());
    expect(wrapper.querySelector('[data-matrix-export-only]')).toBeNull();
  });

  describe('heatmap', () => {
    it('places the toggle between "only used" and the posture, with its tooltip', async () => {
      const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      const onlyUsed = screen.getByRole('button', { name: 'Display only used techniques' });
      const posture = await within(matrixToolbar()).findByRole('combobox', { name: 'Compare with my security posture' });
      expect(onlyUsed.compareDocumentPosition(heatmapToggle()) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(heatmapToggle().compareDocumentPosition(posture) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      expect(heatmapToggle()).toBeEnabled();
      await user.hover(heatmapToggle());
      expect(await screen.findByRole('tooltip')).toHaveTextContent(HEATMAP_LABEL);
    });

    it('disables the toggle without scores and explains why on hover', async () => {
      const { user } = await renderMatrix();
      await screen.findByText('T1001 - Placed');
      expect(heatmapToggle()).toHaveAttribute('aria-disabled', 'true');
      await user.hover(heatmapToggle());
      expect(await screen.findByRole('tooltip')).toHaveTextContent(NO_SCORE_LABEL);
    });

    it('disables the toggle in the empty state', async () => {
      await renderMatrix({ rawObjects: [intrusionSet('is-a', 'APT A')] });
      await screen.findByText('Add attack patterns to the graph view to visualise them here');
      expect(heatmapToggle()).toHaveAttribute('aria-disabled', 'true');
    });

    it('shows the legend only while the heatmap is on', async () => {
      const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();

      await user.click(heatmapToggle());
      expect(within(matrixToolbar()).getByRole('img', { name: 'Technique usage scale, 1 to 2' })).toBeInTheDocument();

      await user.click(heatmapToggle());
      expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();

      await user.click(heatmapToggle());
      expect(screen.getByRole('img', { name: 'Technique usage scale, 1 to 2' })).toBeInTheDocument();
    });

    it('keeps the heatmap and "only used" choices after a switch to the graph view and back', async () => {
      const { user } = await renderMatrix({ rawObjects: SCORED_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      await user.click(heatmapToggle());
      await user.click(screen.getByRole('button', { name: 'Display only used techniques' }));

      await user.click(screen.getByRole('button', { name: 'Switch view (test)' }));
      expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();
      await user.click(screen.getByRole('button', { name: 'Switch view (test)' }));

      expect(await screen.findByRole('img', { name: 'Technique usage scale, 1 to 2' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Display the whole matrix' })).toBeInTheDocument();
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

  describe('filters', () => {
    const filterButton = (name: string) => within(within(matrixToolbar()).getByRole('group', { name: 'Filters' })).getByRole('button', { name });
    const toggleOption = async (user: UserEvent, filter: string, option: string) => {
      await user.click(filterButton(filter));
      await user.click(await screen.findByRole('menuitemcheckbox', { name: option }));
      await user.keyboard('{Escape}');
    };
    const renderFiltered = async () => {
      const rendered = await renderMatrix({ rawObjects: FILTER_OBJECTS, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');
      return rendered;
    };

    it('counts only the links left by the filters in scores, hover names and legend', async () => {
      const { user } = await renderFiltered();
      await user.click(heatmapToggle());
      expect(screen.getByRole('button', { name: 'T1001 - Placed, linked to 2 entities' })).toBeInTheDocument();
      expect(within(matrixToolbar()).getByRole('img', { name: 'Technique usage scale, 1 to 2' })).toBeInTheDocument();

      await toggleOption(user, 'Filter by type', 'Intrusion Set');
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 0 entities' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'T1002 - Parent, linked to 1 entity' })).toBeInTheDocument();
      expect(within(matrixToolbar()).getByRole('img', { name: 'Technique usage scale, 1 to 1' })).toBeInTheDocument();
      expect(filterButton('Filter by type')).toHaveAccessibleName('Filter by type');
      expect(within(matrixToolbar()).getByText('1 in use')).toBeInTheDocument();

      await toggleOption(user, 'Filter by type', 'Intrusion Set');
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 2 entities' })).toBeInTheDocument();

      await toggleOption(user, 'Filter by marking', 'TLP:GREEN');
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 1 entity' })).toBeInTheDocument();
      expect(within(matrixToolbar()).getByRole('img', { name: 'Technique usage scale, 1 to 1' })).toBeInTheDocument();
      // The attack patterns stay those of the whole investigation.
      expect(screen.getByText('T1001 - Placed')).toBeInTheDocument();
    });

    it('turns the heatmap off when the filters leave no score, and back once cleared', async () => {
      const { user } = await renderFiltered();
      await user.click(heatmapToggle());
      expect(heatmapToggle()).toHaveAttribute('aria-pressed', 'true');

      await toggleOption(user, 'Filter by type', 'uses');
      expect(heatmapToggle()).toHaveAttribute('aria-disabled', 'true');
      expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();
      await user.hover(heatmapToggle());
      expect(await screen.findByRole('tooltip')).toHaveTextContent(NO_FILTERED_SCORE_LABEL);
      await user.unhover(heatmapToggle());

      await user.click(filterButton('Clear all filters'));
      expect(heatmapToggle()).toHaveAttribute('aria-pressed', 'true');
      expect(within(matrixToolbar()).getByRole('img', { name: 'Technique usage scale, 1 to 2' })).toBeInTheDocument();
      expect(filterButton('Clear all filters')).toHaveAttribute('aria-disabled', 'true');
    });

    it('blames the filters for no score only when clearing them would bring scores back', async () => {
      // Only a marking no longer in the investigation is stored: the investigation has no score with or without it.
      localStorage.setItem(matrixFiltersStorageKey(INVESTIGATION_ID), JSON.stringify({ disabledMarkings: ['marking--gone'] }));
      const { user } = await renderMatrix();
      await screen.findByText('T1001 - Placed');
      expect(filterButton('Clear all filters')).not.toHaveAttribute('aria-disabled');
      expect(heatmapToggle()).toHaveAttribute('aria-disabled', 'true');
      await user.hover(heatmapToggle());
      const tooltip = await screen.findByRole('tooltip');
      expect(tooltip).toHaveTextContent(NO_SCORE_LABEL);
      expect(tooltip).not.toHaveTextContent(NO_FILTERED_SCORE_LABEL);
    });

    it('keeps the filters, stored, after a switch to the graph view and back', async () => {
      const { user } = await renderFiltered();
      await toggleOption(user, 'Filter by author', 'ACME');
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 1 entity' })).toBeInTheDocument();
      expect(JSON.parse(localStorage.getItem(matrixFiltersStorageKey(INVESTIGATION_ID)) ?? '{}').disabledCreators).toEqual([ACME.id]);

      await user.click(screen.getByRole('button', { name: 'Switch view (test)' }));
      await user.click(screen.getByRole('button', { name: 'Switch view (test)' }));
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 1 entity' })).toBeInTheDocument();
    });

    it('never changes the graph state', async () => {
      const { user } = await renderFiltered();
      await toggleOption(user, 'Filter by type', 'Intrusion Set');
      await toggleOption(user, 'Filter by marking', 'TLP:GREEN');
      await toggleOption(user, 'Filter by author', 'None');
      await user.click(filterButton('Time range'));
      await user.click(screen.getByRole('button', { name: 'Keep January (test)' }));
      await user.click(filterButton('Clear all filters'));
      expect(setGraphState).not.toHaveBeenCalled();
    });

    it('opens the time range under the toolbar and counts only the links in the range', async () => {
      const { user } = await renderFiltered();
      const exportElement = () => document.getElementById(INVESTIGATION_MATRIX_EXPORT_ID) as HTMLElement;
      // Bottom paddings of the captured box and of everything in it.
      const capturedPaddings = () => [exportElement(), ...Array.from(exportElement().querySelectorAll<HTMLElement>('*'))]
        .map((element) => window.getComputedStyle(element).paddingBottom);
      const closedPaddings = capturedPaddings();
      expect(screen.queryByRole('region', { name: 'Time range panel (test)' })).toBeNull();
      expect(exportElement().parentElement?.style.paddingBottom).toBe('');

      await user.click(filterButton('Time range'));
      const panel = screen.getByRole('region', { name: 'Time range panel (test)' });
      expect(filterButton('Time range')).toHaveAttribute('aria-pressed', 'true');
      // The panel reads every scoring relationship, one dot per date.
      expect(within(panel).getByText('Dated links: 3')).toBeInTheDocument();
      expect(within(panel).getByText('Selected: whole range')).toBeInTheDocument();
      // The matrix keeps its bottom rows above the grown toolbar, through a padding kept out of the image and the PDF.
      expect(exportElement().parentElement?.style.paddingBottom).toBe(`${GRAPH_TOOLBAR_HEIGHT_WITH_TIME_RANGE - GRAPH_TOOLBAR_HEIGHT}px`);
      expect(capturedPaddings()).toEqual(closedPaddings);

      await user.click(within(panel).getByRole('button', { name: 'Keep January (test)' }));
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 1 entity' })).toBeInTheDocument();
      expect(within(panel).getByText(`Selected: ${JANUARY.map((date) => date.toISOString()).join(' to ')}`)).toBeInTheDocument();
      expect(JSON.parse(localStorage.getItem(matrixFiltersStorageKey(INVESTIGATION_ID)) ?? '{}').timeRange)
        .toEqual(JANUARY.map((date) => date.toISOString()));

      // Back to the whole range: nothing is stored, so no filter is left to clear.
      await user.click(within(panel).getByRole('button', { name: 'Keep the whole range (test)' }));
      expect(await screen.findByRole('button', { name: 'T1001 - Placed, linked to 2 entities' })).toBeInTheDocument();
      expect(JSON.parse(localStorage.getItem(matrixFiltersStorageKey(INVESTIGATION_ID)) ?? '{}').timeRange).toBeUndefined();
      expect(filterButton('Clear all filters')).toHaveAttribute('aria-disabled', 'true');

      await user.click(filterButton('Time range'));
      expect(screen.queryByRole('region', { name: 'Time range panel (test)' })).toBeNull();
      expect(exportElement().parentElement?.style.paddingBottom).toBe('');
    });

    it('stores no range when the real slider opens on the whole range', async () => {
      timeRangePanel.real = true;
      const consoleError = vi.spyOn(console, 'error');
      // The last link is not a whole number of slider steps (30 minutes) after the first: the slider snaps the end on mount.
      const offGrid = FILTER_OBJECTS.map((object) => (object.id === 'rel-2' ? { ...object, start_time: '2026-03-10T00:07:00.000Z' } : object));
      const { user } = await renderMatrix({ rawObjects: offGrid, phases: HEAT_PHASES });
      await screen.findByText('T1001 - Placed');

      await user.click(filterButton('Time range'));
      expect(filterButton('Time range')).toHaveAttribute('aria-pressed', 'true');
      expect(screen.getAllByRole('slider').length).toBeGreaterThan(0);
      expect(localStorage.getItem(matrixFiltersStorageKey(INVESTIGATION_ID))).toBeNull();
      expect(filterButton('Clear all filters')).toHaveAttribute('aria-disabled', 'true');
      expect(consoleError).not.toHaveBeenCalled();
    });
  });

  it('notifies a failed posture lookup once and still renders the matrix', async () => {
    const { rerender, ui } = await renderMatrix({ postureError: POSTURE_ERROR });
    expect(await screen.findByText('T1001 - Placed')).toBeInTheDocument();
    rerender(ui);
    expect(notifyError).toHaveBeenCalledTimes(1);
  });
});
