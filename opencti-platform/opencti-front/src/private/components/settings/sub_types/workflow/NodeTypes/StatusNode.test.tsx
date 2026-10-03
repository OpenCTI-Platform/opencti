import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { NodeProps } from 'reactflow';
import StatusNode from './StatusNode';
import testRender from '../../../../../../utils/tests/test-render';

vi.mock('reactflow', () => ({
  Handle: () => <div data-testid="handle" />,
  Position: { Top: 'top', Bottom: 'bottom' },
}));

const render = (color?: string) => testRender(
  <StatusNode
    {...({ id: 'n1', data: { statusTemplate: { name: 'in_progress', color } } } as unknown as NodeProps)}
  />,
);

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
});
