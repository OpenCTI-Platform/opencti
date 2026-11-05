import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import en from '../../../../../../lang/front/en.json';
import { buildCellDecorations, type MatrixTechniqueNode } from './buildCellDecorations';
import { analyseTechniqueUsage } from './ttpAnalyser';
import { heatBorder, heatFill } from './heatScale';
import type { LinkedEntity, TechniqueUsage } from './matrixTypes';
import type { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

// The English messages through react-intl, like t_i18n with `values`: ICU plurals are resolved.
const intl = createIntl({ locale: 'en', messages: en });
const t = (s: string, options?: { values?: Record<string, string | number> }) => intl.formatMessage({ id: s }, options?.values);

const NEUTRAL = 'var(--border-elevation-default)';

const entities = (count: number, prefix = 'e'): LinkedEntity[] => (
  Array.from({ length: count }, (_, i) => ({ id: `${prefix}${i}`, name: `${prefix}${String(i).padStart(2, '0')}`, entity_type: 'Malware' }))
);

const usageOf = (attackPatternId: string, linkedEntities: LinkedEntity[]): TechniqueUsage => (
  { attackPatternId, score: linkedEntities.length, linkedEntities }
);

const toMap = (list: TechniqueUsage[]) => new Map(list.map((u) => [u.attackPatternId, u]));

const node = (id: string, mitreId: string, name: string, subs?: MatrixTechniqueNode[]): MatrixTechniqueNode => (
  { attack_pattern_id: id, name, x_mitre_id: mitreId, subAttackPatterns: subs ?? null }
);

// T1074.001 scored 5 (the max), T1074.004 scored 3, T1074 unscored, T1110 present and unscored, T9999 absent.
const sub1 = node('ap-1074-001', 'T1074.001', 'Local Data Staging');
const sub4 = node('ap-1074-004', 'T1074.004', 'Remote Data Staging');
const T1074 = node('ap-1074', 'T1074', 'Data Staged', [sub1, sub4]);
const T1110 = node('ap-1110', 'T1110', 'Brute Force');
const T9999 = node('ap-9999', 'T9999', 'Absent');
const T1059 = node('ap-1059', 'T1059', 'Command and Scripting Interpreter');

const baseUsage = () => toMap([
  usageOf('ap-1074-001', entities(5, 'a')),
  usageOf('ap-1074-004', entities(3, 'b')),
]);

const build = (overrides: Partial<Parameters<typeof buildCellDecorations>[0]> = {}) => buildCellDecorations({
  usage: baseUsage(),
  scale: { max: 5 },
  techniques: [T1074, T1110, T9999],
  investigationIds: new Set(['ap-1074', 'ap-1074-001', 'ap-1074-004', 'ap-1110']),
  heatmapOn: true,
  t,
  ...overrides,
});

describe('buildCellDecorations', () => {
  it('fills a scored sub-technique with its heat stop and dark text', () => {
    const decoration = build().get('ap-1074-001');
    expect(decoration?.fill).toBe(heatFill(4));
    expect(decoration?.textTone).toBe('dark');
    expect(decoration?.border).toBeUndefined();
  });

  it('maps a lower score to a lower stop', () => {
    expect(build().get('ap-1074-004')?.fill).toBe(heatFill(2));
  });

  it('borders an unscored parent in the stop of its highest scoring sub-technique', () => {
    const decoration = build().get('ap-1074');
    expect(decoration?.fill).toBeUndefined();
    expect(decoration?.textTone).toBeUndefined();
    expect(decoration?.border).toBe(heatBorder(4));
  });

  it('borders an unscored parent even when the parent itself is not in the investigation', () => {
    const decoration = build({ investigationIds: new Set(['ap-1074-001', 'ap-1074-004']) }).get('ap-1074');
    expect(decoration?.border).toBe(heatBorder(4));
  });

  it('gives a present, unscored technique the neutral outline and no fill', () => {
    const decoration = build().get('ap-1110');
    expect(decoration?.fill).toBeUndefined();
    expect(decoration?.border).toBe(NEUTRAL);
    expect(decoration?.linkedEntities).toEqual([]);
  });

  it('gives a present, unscored sub-technique the neutral outline', () => {
    const decoration = build({
      usage: toMap([usageOf('ap-1074-001', entities(5, 'a'))]),
      investigationIds: new Set(['ap-1074-001', 'ap-1074-004']),
    }).get('ap-1074-004');
    expect(decoration?.fill).toBeUndefined();
    expect(decoration?.border).toBe(NEUTRAL);
  });

  it('gives a technique absent from the investigation no entry', () => {
    const decorations = build();
    expect(decorations.has('ap-9999')).toBe(false);
    expect(decorations.has('ap-1059')).toBe(false);
  });

  it('lists a parent hover list from its subs, deduplicated and sorted by name', () => {
    const shared = { id: 'shared', name: 'Shared', entity_type: 'Intrusion-Set' };
    const zed = { id: 'zed', name: 'Zed', entity_type: 'Malware' };
    const alpha = { id: 'alpha', name: 'alpha', entity_type: 'Tool' };
    const decoration = build({
      usage: toMap([usageOf('ap-1074-001', [zed, shared]), usageOf('ap-1074-004', [shared, alpha])]),
    }).get('ap-1074');
    expect(decoration?.linkedEntities.map((e) => e.id)).toEqual(['alpha', 'shared', 'zed']);
  });

  it('merges the parent own entities with its subs entities', () => {
    const own = { id: 'own', name: 'Own', entity_type: 'Malware' };
    const sub = { id: 'sub', name: 'Sub', entity_type: 'Tool' };
    const decoration = build({
      usage: toMap([usageOf('ap-1074', [own]), usageOf('ap-1074-001', [sub, own])]),
      scale: { max: 2 },
    }).get('ap-1074');
    expect(decoration?.linkedEntities.map((e) => e.id)).toEqual(['own', 'sub']);
    expect(decoration?.fill).toBe(heatFill(0));
    expect(decoration?.border).toBeUndefined();
  });

  it('keeps every linked entity in the list, leaving truncation to the cell', () => {
    const decoration = build({
      usage: toMap([usageOf('ap-1110', entities(12))]),
      scale: { max: 12 },
    }).get('ap-1110');
    expect(decoration?.linkedEntities).toHaveLength(12);
  });

  it('names a cell with its label and the number of linked entities', () => {
    const decorations = build({
      usage: toMap([usageOf('ap-1059', entities(3))]),
      techniques: [T1059],
      investigationIds: new Set(['ap-1059']),
      scale: { max: 3 },
    });
    expect(decorations.get('ap-1059')?.accessibleName).toBe('T1059 - Command and Scripting Interpreter, linked to 3 entities');
  });

  it('uses the singular for a cell linked to one entity', () => {
    const decorations = build({
      usage: toMap([usageOf('ap-1059', entities(1))]),
      techniques: [T1059],
      investigationIds: new Set(['ap-1059']),
      scale: { max: 1 },
    });
    expect(decorations.get('ap-1059')?.accessibleName).toBe('T1059 - Command and Scripting Interpreter, linked to 1 entity');
  });

  it('names a technique without a MITRE id by its name alone', () => {
    const noId: MatrixTechniqueNode = { attack_pattern_id: 'ap-x', name: 'No Id', x_mitre_id: null };
    const decorations = build({
      usage: toMap([usageOf('ap-x', entities(2))]),
      techniques: [noId],
      investigationIds: new Set(['ap-x']),
      scale: { max: 2 },
    });
    expect(decorations.get('ap-x')?.accessibleName).toBe('No Id, linked to 2 entities');
  });

  it('counts a parent hover list, not only its own score, in the accessible name', () => {
    expect(build().get('ap-1074')?.accessibleName).toBe('T1074 - Data Staged, linked to 8 entities');
  });

  it('keeps the hover list and the accessible name but drops the colours when the heatmap is off', () => {
    const decorations = build({ heatmapOn: false });
    expect(decorations.size).toBe(4);
    decorations.forEach((decoration) => {
      expect(decoration.fill).toBeUndefined();
      expect(decoration.border).toBeUndefined();
      expect(decoration.textTone).toBeUndefined();
    });
    expect(decorations.get('ap-1074-001')?.linkedEntities).toHaveLength(5);
    expect(decorations.get('ap-1074-001')?.accessibleName).toBe('T1074.001 - Local Data Staging, linked to 5 entities');
    expect(decorations.has('ap-9999')).toBe(false);
  });

  it('adds no entry for a parent that is not in the investigation when the heatmap is off', () => {
    const decorations = build({ heatmapOn: false, investigationIds: new Set(['ap-1074-001', 'ap-1074-004']) });
    expect(decorations.has('ap-1074')).toBe(false);
  });

  it('shows the representative of an entity without a name, never undefined', () => {
    const rawObjects = [
      { id: 'ap-1059', entity_type: 'Attack-Pattern', name: 'Command and Scripting Interpreter', parent_types: [] },
      { id: 'ip-1', entity_type: 'IPv4-Addr', observable_value: '1.2.3.4', parent_types: [] },
      { id: 'ind-1', entity_type: 'Indicator', pattern: "[file:name = 'a.exe']", parent_types: [] },
      { id: 'r1', entity_type: 'stix-core-relationship', relationship_type: 'indicates', parent_types: [], from: { id: 'ind-1' }, to: { id: 'ap-1059' } },
      { id: 'r2', entity_type: 'stix-core-relationship', relationship_type: 'uses', parent_types: [], from: { id: 'ip-1' }, to: { id: 'ap-1059' } },
    ] as unknown as ObjectToParse[];
    const usage = analyseTechniqueUsage(rawObjects);
    const decoration = buildCellDecorations({
      usage,
      scale: { max: 2 },
      techniques: [T1059],
      investigationIds: new Set(['ap-1059']),
      heatmapOn: true,
      t,
    }).get('ap-1059');
    expect(decoration?.linkedEntities.map((e) => e.name)).toEqual(["[file:name = 'a.exe']", '1.2.3.4']);
    expect(decoration?.accessibleName).toBe('T1059 - Command and Scripting Interpreter, linked to 2 entities');
    expect(JSON.stringify(decoration)).not.toContain('undefined');
  });
});
