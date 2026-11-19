import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render } from '@testing-library/react';
import ReactFlow, { Position, type Node, type NodeProps } from 'reactflow';
import PlaybookPortHandle from './PlaybookPortHandle';
import { playbookHandleHint } from './PlaybookHandleHint';

const onOpen = vi.fn();

// A step with one labelled port, drawn the way NodeWorkflow draws it.
const StepWithPill = ({ id, isConnectable }: NodeProps) => (
  <div style={{ width: 264, height: 104 }}>
    <PlaybookPortHandle
      portId="unmatch"
      portName="pas de correspondance"
      nodeId={id}
      position={Position.Right}
      anchor={{ x: 264, y: 52 }}
      direction="horizontal"
      accent="#00f"
      background="#fff"
      isConnectable={isConnectable}
      opensSettings
      onOpen={onOpen}
    />
  </div>
);

const nodeTypes = { step: StepWithPill };
const nodes: Node[] = [{ id: 'reduce', type: 'step', position: { x: 0, y: 0 }, data: {} }];

const renderCanvas = (props: Partial<React.ComponentProps<typeof ReactFlow>>) => render(
  <div style={{ width: 800, height: 600 }}>
    <ReactFlow defaultNodes={nodes} nodeTypes={nodeTypes} {...props} />
  </div>,
);

// React Flow starts a connection from the element under the pointer; jsdom does no hit testing, so the
// element under the pointer is the one the test presses.
const pressOn = (element: Element) => {
  const original = document.elementFromPoint;
  document.elementFromPoint = () => element;
  fireEvent.mouseDown(element, { button: 0, clientX: 10, clientY: 10 });
  fireEvent.mouseUp(element, { button: 0, clientX: 10, clientY: 10 });
  document.elementFromPoint = original;
};

describe('labelled port pill', () => {
  afterEach(() => onOpen.mockReset());

  it('is the source handle itself, with the full name as its only content', () => {
    const { getByTestId } = renderCanvas({});
    const pill = getByTestId('playbook-port-reduce-unmatch');
    expect(pill.classList.contains('react-flow__handle')).toBe(true);
    expect(pill.classList.contains('source')).toBe(true);
    expect(pill.getAttribute('data-handleid')).toBe('unmatch');
    expect(pill.getAttribute('title')).toBe('pas de correspondance');
    // No child element: whatever point of the pill is pressed, the element under the pointer is the handle.
    expect(pill.children.length).toBe(0);
    expect(pill.textContent).toBe('pas de correspondance');
  });

  it('starts a connection on a pointer down anywhere on the pill in edit mode', () => {
    const onConnectStart = vi.fn();
    const { getByTestId } = renderCanvas({ nodesConnectable: true, onConnectStart });
    pressOn(getByTestId('playbook-port-reduce-unmatch'));
    expect(onConnectStart).toHaveBeenCalledTimes(1);
    expect(onConnectStart.mock.calls[0][1]).toEqual({ nodeId: 'reduce', handleId: 'unmatch', handleType: 'source' });
  });

  it('starts no connection in view mode', () => {
    const onConnectStart = vi.fn();
    const { getByTestId } = renderCanvas({ nodesConnectable: false, onConnectStart });
    pressOn(getByTestId('playbook-port-reduce-unmatch'));
    expect(onConnectStart).not.toHaveBeenCalled();
  });

  it('says what a drag from a connection point does in edit mode only', () => {
    expect(playbookHandleHint(true, 'drag hint')).toBe('drag hint');
    // View mode: no hint, so the pill keeps its full name as its title and nothing suggests a drag.
    expect(playbookHandleHint(false, 'drag hint')).toBeUndefined();
  });

  it('opens the step configuration on a click', () => {
    const { getByTestId } = renderCanvas({ nodesConnectable: true });
    fireEvent.click(getByTestId('playbook-port-reduce-unmatch'));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});
