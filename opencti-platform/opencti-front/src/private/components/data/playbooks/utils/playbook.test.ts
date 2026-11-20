import { describe, expect, it } from 'vitest';
import { computeNodes, linkedOutPorts, placeholderEdgeIdOf, placeholderIdOf } from './playbook';
import type { PlaybookDefinitionEdge, PlaybookDefinitionNode } from '../types/playbook-types';

describe('Playbook add buttons', () => {
  it('names the "+" of a free out port after its step and its port', () => {
    expect(placeholderIdOf('step-1', 'no-match')).toBe('step-1-no-match-PLACEHOLDER');
    expect(placeholderEdgeIdOf('step-1', 'no-match')).toBe('step-1-no-match-step-1-no-match-PLACEHOLDER');
  });

  it('gives the same "+" the same id every time, so an edit and a reload draw the same button', () => {
    expect(placeholderIdOf('step-1', 'out')).toBe(placeholderIdOf('step-1', 'out'));
    expect(placeholderIdOf('step-1', 'out')).not.toBe(placeholderIdOf('step-1', 'no-match'));
    expect(placeholderIdOf('step-1', 'out')).not.toBe(placeholderIdOf('step-2', 'out'));
  });
});

describe('Steps whose component is not in the catalog', () => {
  const links: PlaybookDefinitionEdge[] = [
    { id: 'l1', from: { id: 'ai', port: 'unmodified' }, to: { id: 'log' } },
    { id: 'l2', from: { id: 'ai', port: 'out' }, to: { id: 'next' } },
    { id: 'l3', from: { id: 'other', port: 'out' }, to: { id: 'ai' } },
  ];
  const node = (id: string, component_id: string): PlaybookDefinitionNode => ({
    id, name: id, component_id, configuration: '{}', position: { x: 0, y: 0 },
  });

  it('lists the out ports its links leave from, out first, each once', () => {
    expect(linkedOutPorts('ai', links)).toEqual(['out', 'unmodified']);
    expect(linkedOutPorts('log', links)).toEqual([]);
  });

  it('keeps a port for every link of an unavailable step, none for a known one', () => {
    const known = { id: 'PLAYBOOK_LOGGER_COMPONENT', ports: [{ id: 'out', type: 'out' }] } as never;
    const nodes = computeNodes([node('ai', 'PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT'), node('log', 'PLAYBOOK_LOGGER_COMPONENT')], [known], () => {}, () => {}, links);
    expect(nodes[0].data.component).toBeUndefined();
    expect(nodes[0].data.linkedPorts).toEqual(['out', 'unmodified']);
    expect(nodes[1].data.linkedPorts).toBeUndefined();
  });
});
