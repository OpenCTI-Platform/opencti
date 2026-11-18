import React from 'react';
import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import ReactFlow, { type Edge, type Node, type NodeProps } from 'reactflow';
import playbookFlowKeyboardProps from './playbookFlowKeyboard';

// A card shaped like a playbook step: its own title button and menu button.
const CardWithButtons = ({ data }: NodeProps<{ label: string }>) => (
  <div>
    <button type="button">{data.label}</button>
    <button type="button" aria-label="Step menu">...</button>
  </div>
);

const nodeTypes = { card: CardWithButtons };
const nodes: Node[] = [
  { id: 'a', type: 'card', position: { x: 0, y: 0 }, data: { label: 'Update: Qualify report' } },
  { id: 'b', type: 'card', position: { x: 0, y: 200 }, data: { label: 'Filter' } },
];
const edges: Edge[] = [{ id: 'a-b', source: 'a', target: 'b' }];

const renderCanvas = (props: Partial<React.ComponentProps<typeof ReactFlow>>) => render(
  <div style={{ width: 800, height: 600 }}>
    <ReactFlow defaultNodes={nodes} defaultEdges={edges} nodeTypes={nodeTypes} {...props} />
  </div>,
);

describe('playbook canvas keyboard path', () => {
  it('never wraps a card that holds buttons in a focusable role=button', () => {
    const { container } = renderCanvas(playbookFlowKeyboardProps);
    const wrappers = container.querySelectorAll('.react-flow__node');
    expect(wrappers.length).toBe(2);
    wrappers.forEach((wrapper) => {
      expect(wrapper.getAttribute('role')).not.toBe('button');
      expect(wrapper.hasAttribute('tabindex')).toBe(false);
      expect(wrapper.querySelectorAll('button').length).toBe(2);
    });
  });

  it('keeps links out of the Tab order', () => {
    const { container } = renderCanvas(playbookFlowKeyboardProps);
    container.querySelectorAll('.react-flow__edge').forEach((edge) => {
      expect(edge.getAttribute('tabindex')).not.toBe('0');
    });
  });

  it('documents the default this guards against', () => {
    const { container } = renderCanvas({});
    const wrapper = container.querySelector('.react-flow__node');
    expect(wrapper?.getAttribute('role')).toBe('button');
  });
});
