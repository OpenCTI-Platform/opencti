import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { NodeProps } from 'reactflow';
import StatusNode from './StatusNode';
import testRender from '../../../../../../utils/tests/test-render';
import { HoverHighlightContext } from '../hoverHighlight';

vi.mock('reactflow', () => ({
  Handle: () => <div data-testid="handle" />,
  Position: { Top: 'top', Bottom: 'bottom' },
}));

// hover: 'lit' when this node is in the hovered neighbourhood, 'dimmed' when another one is hovered.
const render = (color?: string, hover?: 'lit' | 'dimmed') => testRender(
  <HoverHighlightContext.Provider value={hover ? { nodeIds: new Set([hover === 'lit' ? 'n1' : 'other']), edgeIds: new Set() } : null}>
    <StatusNode
      {...({ id: 'n1', data: { statusTemplate: { name: 'in_progress', color } } } as unknown as NodeProps)}
    />
  </HoverHighlightContext.Provider>,
);
const chipBox = () => {
  const chip = screen.getByText('In progress').closest('[style]') as HTMLElement;
  return chip.style.justifyContent ? chip : (chip.parentElement as HTMLElement);
};

describe('StatusNode', () => {
  it('centres its label and carries a full-opacity border of the status colour', () => {
    render('#ff9800');
    const chip = screen.getByText('In progress').closest('[style]') as HTMLElement;
    const box = chip.style.border ? chip : (chip.parentElement as HTMLElement);
    expect(box.style.justifyContent).toBe('center');
    expect(box.style.border).toBe('1px solid rgb(255, 152, 0)');
    // the label inherits this; the host stylesheet turns the chip's own ink off
    expect(box.style.color).toBe('rgb(255, 152, 0)');
    // the label is no longer shouted
    expect(box.style.textTransform).toBe('');
    // 10% of the status colour, the alpha hexToRGB defaults to
    expect(box.style.backgroundColor).toBe('rgba(255, 152, 0, 0.1)');
  });

  it('leaves the border out when the status template has no colour', () => {
    render(undefined);
    const chip = screen.getByText('In progress').closest('[style]') as HTMLElement;
    const box = chip.style.justifyContent ? chip : (chip.parentElement as HTMLElement);
    expect(box.style.border).toBe('');
    expect(box.style.color).toBe('');
    expect(box.style.backgroundColor).toBe('');
  });

  it('doubles its border and thickens its label while highlighted, without changing its size', () => {
    render('#ff9800', 'lit');
    const box = chipBox();
    expect(box.style.border).toBe('1px solid rgb(255, 152, 0)');
    expect(box.style.boxShadow).toBe('0 0 0 0.5px #ff9800');
    expect(box.style.textShadow).not.toBe('');
  });

  it('keeps a single border and a plain label when not highlighted', () => {
    render('#ff9800');
    expect(chipBox().style.boxShadow).toBe('');
    expect(chipBox().style.textShadow).toBe('');
  });

  it('fades while another node is hovered', () => {
    const { container } = render('#ff9800', 'dimmed');
    expect(container.querySelector<HTMLElement>('.workflow-status-node')!.style.opacity).toBe('0.3');
  });
});
