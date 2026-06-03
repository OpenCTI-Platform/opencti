import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import PlaceholderNode from './PlaceholderNode';
import type { NodeProps, Position } from 'reactflow';

vi.mock('reactflow', () => ({
  Handle: ({ id, type }: { id: string; type: string }) => (
    <div data-testid={`handle-${id}`} data-type={type} />
  ),
  Position: { Top: 'top', Bottom: 'bottom' },
}));

vi.mock('@mui/styles', () => ({
  useTheme: () => ({
    palette: {
      mode: 'dark',
      background: {},
    },
  }),
}));

// ---------------------------------------------------------------------------
// Theme + helper
// ---------------------------------------------------------------------------
const testTheme = createTheme({ palette: { mode: 'dark' } });
const renderWithTheme = (component: React.ReactElement) =>
  render(<ThemeProvider theme={testTheme}>{component}</ThemeProvider>);

const makeProps = (id = 'placeholder-1'): NodeProps => ({
  id,
  data: {},
  selected: false,
  type: 'placeholder',
  xPos: 0,
  yPos: 0,
  zIndex: 0,
  isConnectable: true,
  dragging: false,
  sourcePosition: 'bottom' as unknown as Position,
  targetPosition: 'top' as unknown as Position,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('PlaceholderNode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders a "+" label', () => {
    renderWithTheme(<PlaceholderNode {...makeProps()} />);
    expect(screen.getByText('+')).toBeInTheDocument();
  });

  it('renders a target handle (hidden)', () => {
    renderWithTheme(<PlaceholderNode {...makeProps()} />);
    expect(screen.getByTestId('handle-target')).toBeInTheDocument();
  });

  it('changes chip color on mouse enter (isHover → true)', () => {
    renderWithTheme(<PlaceholderNode {...makeProps()} />);
    // The Chip has an inline style with a low opacity before hover
    const chip = screen.getByText('+').closest('.MuiChip-root') as HTMLElement;
    const colorBefore = chip.style.color;
    fireEvent.mouseEnter(chip);
    const colorAfter = chip.style.color;
    // Opacity changes from 0.04 to 0.2 on hover
    expect(colorAfter).not.toBe(colorBefore);
  });

  it('resets chip color after mouse leave (isHover → false)', () => {
    renderWithTheme(<PlaceholderNode {...makeProps()} />);
    const chip = screen.getByText('+').closest('.MuiChip-root') as HTMLElement;
    const colorBefore = chip.style.color;
    fireEvent.mouseEnter(chip);
    fireEvent.mouseLeave(chip);
    const colorAfterLeave = chip.style.color;
    expect(colorAfterLeave).toBe(colorBefore);
  });
});
