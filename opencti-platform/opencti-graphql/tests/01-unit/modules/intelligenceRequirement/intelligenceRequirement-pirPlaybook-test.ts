import { describe, expect, it } from 'vitest';
import { PLAYBOOK_DATA_STREAM_PIR_ID, rewritePlaybookDefinition } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-pirPlaybook';
import { PLAYBOOK_DATA_STREAM_REQUIREMENT_ID } from '../../../../src/modules/playbook/components/data-stream-requirement-component';

const sourceFilters = JSON.stringify({ mode: 'and', filterGroups: [], filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }] });

const pirEntry = (inPirFilters: unknown, extra: Record<string, unknown> = {}) => ({
  id: 'entry',
  name: 'Listen PIR events',
  position: { x: 10, y: 20 },
  component_id: PLAYBOOK_DATA_STREAM_PIR_ID,
  configuration: JSON.stringify({ create: true, create_rel: true, update: false, delete: true, inPirFilters, filters: sourceFilters, ...extra }),
});

const logger = { id: 'log', name: 'Log', position: { x: 10, y: 120 }, component_id: 'PLAYBOOK_LOGGER_COMPONENT', configuration: '{"level":"debug"}' };
const link = { id: 'link', from: { id: 'entry', port: 'out' }, to: { id: 'log' } };

const definition = (entry: object) => JSON.stringify({ nodes: [entry, logger], links: [link] });
const requirements = new Map([['pir-a', 'ir-a'], ['pir-b', 'ir-b']]);

describe('Pir migration: playbook rewrite', () => {
  it('should turn a "Listen PIR events" entry into the requirement entry on the requirements of its Pirs', () => {
    const rewrite = rewritePlaybookDefinition(definition(pirEntry([{ value: 'pir-a', label: 'Europe' }, { value: 'pir-b' }])), requirements);
    expect(rewrite.changed).toBe(true);
    expect(rewrite.unmapped).toEqual([]);
    const parsed = JSON.parse(rewrite.definition);
    const entry = parsed.nodes[0];
    expect(entry.component_id).toEqual(PLAYBOOK_DATA_STREAM_REQUIREMENT_ID);
    // same node: id, name, position and links kept, so playbook_start and the graph are unchanged
    expect(entry.id).toEqual('entry');
    expect(entry.position).toEqual({ x: 10, y: 20 });
    expect(parsed.links).toEqual([link]);
    expect(parsed.nodes[1]).toEqual(logger);
    const configuration = JSON.parse(entry.configuration);
    expect(configuration.requirementFilters).toEqual([{ value: 'ir-a', label: 'Europe' }, { value: 'ir-b' }]);
    expect(configuration.inPirFilters).toBeUndefined();
    // toggles and source filters kept as they are
    expect([configuration.create, configuration.create_rel, configuration.update, configuration.delete]).toEqual([true, true, false, true]);
    expect(configuration.filters).toEqual(sourceFilters);
  });

  it('should keep an entry on every requirement when no Pir was selected', () => {
    const rewrite = rewritePlaybookDefinition(definition(pirEntry([])), requirements);
    expect(rewrite.changed).toBe(true);
    expect(JSON.parse(JSON.parse(rewrite.definition).nodes[0].configuration).requirementFilters).toEqual([]);
  });

  it('should never half rewrite a playbook naming a Pir that was not converted', () => {
    const original = definition(pirEntry([{ value: 'pir-a' }, { value: 'pir-kept' }]));
    const rewrite = rewritePlaybookDefinition(original, requirements);
    expect(rewrite.changed).toBe(false);
    expect(rewrite.unmapped).toEqual(['pir-kept']);
    expect(rewrite.definition).toEqual(original);
  });

  it('should ignore malformed inPirFilters values and keep the rest', () => {
    const rewrite = rewritePlaybookDefinition(definition(pirEntry([{ value: 'pir-a' }, 'garbage', { value: 42 }, null])), requirements);
    expect(rewrite.changed).toBe(true);
    expect(JSON.parse(JSON.parse(rewrite.definition).nodes[0].configuration).requirementFilters).toEqual([{ value: 'ir-a' }]);
  });

  it('should leave a playbook without a PIR entry untouched (idempotent on a rewritten playbook)', () => {
    const first = rewritePlaybookDefinition(definition(pirEntry([{ value: 'pir-a' }])), requirements);
    const second = rewritePlaybookDefinition(first.definition, requirements);
    expect(second).toEqual({ definition: first.definition, changed: false, unmapped: [] });
    expect(rewritePlaybookDefinition('not json', requirements)).toEqual({ definition: 'not json', changed: false, unmapped: [] });
  });

  it('should rewrite every PIR entry of a playbook that has several', () => {
    const second = { ...pirEntry([{ value: 'pir-b' }]), id: 'entry-2' };
    const rewrite = rewritePlaybookDefinition(JSON.stringify({ nodes: [pirEntry([{ value: 'pir-a' }]), second], links: [] }), requirements);
    const nodes = JSON.parse(rewrite.definition).nodes;
    expect(nodes.map((n: { component_id: string }) => n.component_id)).toEqual([PLAYBOOK_DATA_STREAM_REQUIREMENT_ID, PLAYBOOK_DATA_STREAM_REQUIREMENT_ID]);
    expect(JSON.parse(nodes[1].configuration).requirementFilters).toEqual([{ value: 'ir-b' }]);
  });
});
