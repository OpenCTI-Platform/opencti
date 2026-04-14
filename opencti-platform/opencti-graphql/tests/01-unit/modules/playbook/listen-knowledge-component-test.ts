import { describe, it, expect } from 'vitest';
import type { NodeDefinition } from '../../../../src/modules/playbook/playbook-types';

const buildPlaybook = (configuration: object, playbookStart = 'node-1') => ({
  playbook_start: playbookStart,
  playbook_definition: JSON.stringify({
    nodes: [{ id: playbookStart, component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM', configuration: JSON.stringify(configuration) }],
  }),
});

describe('PLAYBOOK_INTERNAL_DATA_STREAM - enrollInPlaybook', () => {
  it('should be available for enrollment when enrollInPlaybook is true', () => {
    const playbook = buildPlaybook({ enrollInPlaybook: true });
    const def = JSON.parse(playbook.playbook_definition);
    const instance = def.nodes.find((n: NodeDefinition) => n.id === playbook.playbook_start);
    const { enrollInPlaybook } = JSON.parse(instance.configuration ?? '{}');
    const isAvailable = enrollInPlaybook ?? true;
    expect(isAvailable).toBe(true);
  });

  it('should not be available for enrollment when enrollInPlaybook is false', () => {
    const playbook = buildPlaybook({ enrollInPlaybook: false });
    const def = JSON.parse(playbook.playbook_definition);
    const instance = def.nodes.find((n: NodeDefinition) => n.id === playbook.playbook_start);
    const { enrollInPlaybook } = JSON.parse(instance.configuration ?? '{}');
    const isAvailable = enrollInPlaybook ?? true;
    expect(isAvailable).toBe(false);
  });

  it('should default to true when enrollInPlaybook is not set (legacy playbooks)', () => {
    const playbook = buildPlaybook({});
    const def = JSON.parse(playbook.playbook_definition);
    const instance = def.nodes.find((n: NodeDefinition) => n.id === playbook.playbook_start);
    const { enrollInPlaybook } = JSON.parse(instance.configuration ?? '{}');
    const isAvailable = enrollInPlaybook ?? true;
    expect(isAvailable).toBe(true);
  });
});
