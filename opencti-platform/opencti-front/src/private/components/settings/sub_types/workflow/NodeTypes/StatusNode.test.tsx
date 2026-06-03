import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import StatusNode from './StatusNode';
import type { NodeProps, Position } from 'reactflow';

vi.mock('reactflow', () => ({
  Handle: ({ id, type, position }: { id: string; type: string; position: string }) => (
    <div data-testid={`handle-${id}`} data-type={type} data-position={position} />
  ),
  Position: { Top: 'top', Bottom: 'bottom' },
}));

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
const testTheme = createTheme({ palette: { mode: 'dark' } });
const renderWithTheme = (component: React.ReactElement) =>
  render(<ThemeProvider theme={testTheme}>{component}</ThemeProvider>);

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
const makeProps = (overrides: Record<string, unknown> = {}): NodeProps => ({
  id: 'status-1',
  data: {
    statusTemplate: { id: 'st-1', name: 'Open', color: '#00FF00' },
    ...overrides,
  },
  selected: false,
  type: 'status',
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
describe('StatusNode', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the status label from statusTemplate.name', () => {
    renderWithTheme(<StatusNode {...makeProps()} />);
    expect(screen.getByText('Open')).toBeInTheDocument();
  });

  it('applies snakeCaseToSentenceCase to multi-word names', () => {
    renderWithTheme(
      <StatusNode
        {...makeProps({ statusTemplate: { id: 'st-2', name: 'in_progress', color: '#FF0000' } })}
      />,
    );
    expect(screen.getByText('In progress')).toBeInTheDocument();
  });

  it('renders a target handle at the top', () => {
    renderWithTheme(<StatusNode {...makeProps()} />);
    const handle = screen.getByTestId('handle-target');
    expect(handle).toBeInTheDocument();
    expect(handle.dataset.type).toBe('target');
    expect(handle.dataset.position).toBe('top');
  });

  it('renders a source handle at the bottom', () => {
    renderWithTheme(<StatusNode {...makeProps()} />);
    const handle = screen.getByTestId('handle-source');
    expect(handle).toBeInTheDocument();
    expect(handle.dataset.type).toBe('source');
    expect(handle.dataset.position).toBe('bottom');
  });
});
