import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationMatrixToolbar, { type InvestigationMatrixToolbarProps } from './InvestigationMatrixToolbar';
import { DEFAULT_INVESTIGATION_MATRIX_SETTINGS } from './investigationMatrixSettings';
import type { InvestigationAttackPattern } from './investigationMatrixUtils';

// The row is as wide as each test sets it.
const row = vi.hoisted(() => ({ width: 2000 }));
vi.mock('../../../../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: row.width, height: 54 }) }));

const granted = vi.hoisted(() => ({ value: true }));
vi.mock('../../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../utils/hooks/useGranted')>()),
  default: () => granted.value,
}));

const imageExport = vi.hoisted(() => ({
  options: [{ key: 'dark:bg', label: 'Dark (with background)' }],
  exporting: false,
  exportImage: vi.fn(),
}));
vi.mock('./useMatrixImageExport', () => ({ useMatrixImageExport: () => imageExport }));

// The platform search behind the field is not what these tests are about.
vi.mock('@components/common/form/EntitySelect', () => ({
  default: ({ label, disabled }: { label: string; disabled?: boolean }) => <input aria-label={label} disabled={disabled} />,
}));

const HEATMAP_LABEL = 'Displays heat map of attack pattern use';
const POSTURE_LABEL = 'Compare with my security posture';

const outside = (count: number): InvestigationAttackPattern[] => Array.from({ length: count }, (_, index) => ({
  id: `attack-pattern--${index}`,
  name: String.fromCharCode(65 + index),
  x_mitre_id: `T${1001 + index}`,
}));

const renderToolbar = (props: Partial<InvestigationMatrixToolbarProps> = {}) => {
  const element = (
    <InvestigationMatrixToolbar
      outsideKillChain={[]}
      killChains={['mitre-attack']}
      killChain="mitre-attack"
      settings={DEFAULT_INVESTIGATION_MATRIX_SETTINGS}
      onSettingsChange={vi.fn()}
      onSecurityPlatformsChange={vi.fn()}
      isEmpty={false}
      hasScores
      heatmapOn={false}
      heatMax={4}
      exportName="Investigation - Matrix view"
      {...props}
    />
  );
  return { element, ...testRender(element) };
};

const toolbar = () => screen.getByRole('toolbar', { name: 'Matrix toolbar' });

describe('InvestigationMatrixToolbar', () => {
  beforeEach(() => {
    // The labelled pinned parts (display, heatmap) take 205 px, the posture field 200 px; nothing else is measured.
    // At 700 px the posture fits and the export does not; at 500 px neither does.
    // A spy, restored after each test: deleting the getter would leave the next test files of the worker without it.
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function offsetWidth(this: HTMLElement) {
      if (this.getAttribute('data-toolbar-action') === 'posture') return 200;
      if (this.hasAttribute('data-toolbar-pinned') && this.getAttribute('aria-label')) return 205;
      return 0;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    row.width = 2000;
    granted.value = true;
    imageExport.exporting = false;
  });

  it('shows the matrix controls and none of the graph-only tools', () => {
    renderToolbar();
    const bar = toolbar();
    expect(within(bar).getByRole('combobox', { name: 'Kill chain' })).toHaveTextContent('mitre-attack');
    expect(within(bar).getByRole('button', { name: 'Display only used techniques' })).toBeInTheDocument();
    expect(within(bar).getByRole('button', { name: HEATMAP_LABEL })).toBeInTheDocument();
    expect(within(bar).getByRole('textbox', { name: POSTURE_LABEL })).toBeInTheDocument();
    expect(within(bar).getByRole('button', { name: 'Export to image' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Zoom in|Fit the whole graph|Keyboard shortcuts|Add an entity/ })).toBeNull();
    expect(screen.queryByRole('searchbox')).toBeNull();
  });

  it('counts the attack patterns outside the kill chain and lists them by T-code on hover', async () => {
    const { user } = renderToolbar({ outsideKillChain: outside(12) });
    const note = within(toolbar()).getByText('12 attack patterns not shown');
    await user.hover(note);
    const tooltip = await screen.findByRole('tooltip');
    expect(tooltip).toHaveTextContent('Outside the selected kill chain (12)');
    expect(tooltip).toHaveTextContent('T1001 - A');
    expect(tooltip).toHaveTextContent('T1010 - J');
    expect(tooltip).not.toHaveTextContent('T1011 - K');
    expect(tooltip).toHaveTextContent('and 2 more');
  });

  it('shows no note when every attack pattern is in the kill chain', () => {
    renderToolbar();
    expect(screen.queryByText(/not shown/)).toBeNull();
  });

  it('shows the legend only while the heatmap is on', () => {
    const { rerender, element } = renderToolbar();
    expect(screen.queryByRole('img', { name: /Technique usage scale/ })).toBeNull();
    rerender(React.cloneElement(element, { heatmapOn: true }));
    expect(within(toolbar()).getByRole('img', { name: 'Technique usage scale, 1 to 4' })).toBeInTheDocument();
    expect(within(toolbar()).getByRole('button', { name: HEATMAP_LABEL })).toHaveAttribute('aria-pressed', 'true');
  });

  it('turns the heatmap on and off from its toggle', async () => {
    const onSettingsChange = vi.fn();
    const { user } = renderToolbar({ onSettingsChange });
    await user.click(within(toolbar()).getByRole('button', { name: HEATMAP_LABEL }));
    expect(onSettingsChange).toHaveBeenCalledWith({ heatmap: true });
  });

  it('disables the heatmap without scores and says why', async () => {
    const { user } = renderToolbar({ hasScores: false });
    const toggle = within(toolbar()).getByRole('button', { name: HEATMAP_LABEL });
    expect(toggle).toHaveAttribute('aria-disabled', 'true');
    await user.hover(toggle);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('No attack pattern is linked to an entity in this investigation');
  });

  it('moves export then posture to "More actions" when the row shrinks, the posture as a submenu', async () => {
    const { user, rerender, element } = renderToolbar();
    expect(screen.queryByRole('button', { name: 'More actions' })).toBeNull();

    row.width = 700;
    rerender(element);
    expect(within(toolbar()).queryByRole('button', { name: 'Export to image' })).toBeNull();
    expect(within(toolbar()).getByRole('textbox', { name: POSTURE_LABEL })).toBeInTheDocument();

    row.width = 500;
    rerender(element);
    expect(within(toolbar()).queryByRole('textbox', { name: POSTURE_LABEL })).toBeNull();
    // Pinned whatever the room.
    expect(within(toolbar()).getByRole('combobox', { name: 'Kill chain' })).toBeInTheDocument();
    expect(within(toolbar()).getByRole('button', { name: HEATMAP_LABEL })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'More actions' }));
    expect(await screen.findByRole('menuitem', { name: 'Export to image' })).toBeInTheDocument();
    await user.click(screen.getByRole('menuitem', { name: POSTURE_LABEL }));
    expect(await screen.findByRole('textbox', { name: POSTURE_LABEL })).toBeInTheDocument();
  });

  it('offers the image export only to a user allowed to export', () => {
    granted.value = false;
    renderToolbar();
    expect(screen.queryByRole('button', { name: 'Export to image' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'More actions' })).toBeNull();
  });

  it('lists the image options of each theme and exports the one chosen', async () => {
    const { user } = renderToolbar();
    await user.click(within(toolbar()).getByRole('button', { name: 'Export to image' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Dark (with background)' }));
    expect(imageExport.exportImage).toHaveBeenCalledWith('dark:bg');
  });

  it('disables the image export while one runs', () => {
    imageExport.exporting = true;
    renderToolbar();
    expect(within(toolbar()).getByRole('button', { name: 'Export to image' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByText('Export in progress')).toBeInTheDocument();
  });
});
