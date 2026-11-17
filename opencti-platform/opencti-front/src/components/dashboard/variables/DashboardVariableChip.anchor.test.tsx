import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardVariable } from '../dashboard-types';
import DashboardVariableChip from './DashboardVariableChip';

// The popover is positioned from its anchor element: jsdom lays nothing out, so the anchor it receives is
// recorded instead. An anchor no longer in the page has no position, and the browser shows the popover in the
// top left corner of the screen (#20106).
const popover = vi.hoisted(() => ({ anchorEl: null as Element | null }));
type Anchor = Element | null | (() => Element | null);

vi.mock('@mui/material/Popover', () => ({
  default: ({ open, anchorEl, children }: { open: boolean; anchorEl: Anchor; children: ReactNode }) => {
    // The anchor is resolved when the popover positions itself, after the render, as MUI does.
    popover.anchorEl = typeof anchorEl === 'function' ? anchorEl() : anchorEl;
    return open ? <div data-testid="variable-popover">{children}</div> : null;
  },
}));

vi.mock('./useVariableValueLabels', () => ({
  default: (_variable: unknown, values: string[]) => ({ labels: new Map(values.map((value) => [value, value])), restricted: new Set() }),
}));

const confidence: DashboardVariable = {
  id: 'var-1',
  name: 'Min confidence',
  type: 'numeric',
  restriction: { mode: 'none' },
  defaultValue: '50',
};

type ChipProps = Partial<React.ComponentProps<typeof DashboardVariableChip>>;
const chipOf = (props: ChipProps) => (
  <DashboardVariableChip variable={confidence} value="50" usedInWidgetIds={['w-1']} onChange={vi.fn()} {...props} />
);

// Opens the popover from the chip, then gives the chip the next props while the popover is open.
const openThenRerender = async (before: ChipProps, after: ChipProps, name: string) => {
  const { user, rerender } = testRender(chipOf(before));
  await user.click(screen.getByRole('button', { name }));
  expect(screen.getByTestId('variable-popover')).toBeInTheDocument();
  rerender(chipOf(after));
  expect(screen.getByTestId('variable-popover')).toBeInTheDocument();
};

// The anchor is the container of the chip itself: a farther ancestor (the bar, the body) would also hold the chip,
// with the popover far from it.
const expectAnchoredOnChip = () => {
  const { anchorEl } = popover;
  expect(anchorEl).not.toBeNull();
  expect(anchorEl?.isConnected).toBe(true);
  expect(anchorEl).toBe(screen.getByTestId('dashboard-variable-chip-Min confidence'));
  expect(anchorEl).toContainElement(screen.getByRole('button', { name: /^Min confidence : / }));
};

describe('DashboardVariableChip popover anchor', () => {
  beforeEach(() => {
    popover.anchorEl = null;
  });

  it('stays anchored on the chip when a changed value makes the chip modified', async () => {
    await openThenRerender({ value: '50', modified: false }, { value: '78', modified: true }, 'Min confidence : 50');
    expectAnchoredOnChip();
  });

  it('stays anchored on the chip when the value goes back to its base', async () => {
    await openThenRerender({ value: '78', modified: true }, { value: '50', modified: false }, 'Min confidence : 78');
    expectAnchoredOnChip();
  });

  it('stays anchored on the chip when the variable stops being used by any widget', async () => {
    await openThenRerender({ usedInWidgetIds: ['w-1'] }, { usedInWidgetIds: [] }, 'Min confidence : 50');
    expectAnchoredOnChip();
  });

  it('stays anchored on the chip when it is disabled for a while, then enabled again', async () => {
    // The chip button is wrapped while disabled (a preset being saved): it is mounted again both ways.
    const { user, rerender } = testRender(chipOf({}));
    await user.click(screen.getByRole('button', { name: 'Min confidence : 50' }));
    rerender(chipOf({ disabled: true }));
    expect(screen.queryByTestId('variable-popover')).not.toBeInTheDocument();
    rerender(chipOf({ disabled: false }));
    expect(screen.getByTestId('variable-popover')).toBeInTheDocument();
    expectAnchoredOnChip();
  });
});
