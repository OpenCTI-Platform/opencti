import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import en from '../../../../../../lang/front/en.json';
import { buildProcedureCellDecorations, buildProcedureUsage, heatmapTechniqueIds, type HeatTechniqueNode } from './procedureHeatmap';
import { computeHeatScale, heatBorder, heatFill } from '../../../workspaces/investigations/matrix/heatScale';

// The English messages through react-intl, like t_i18n with `values`: ICU plurals are resolved.
const intl = createIntl({ locale: 'en', messages: en });
const t = (s: string, options?: { values?: Record<string, string | number> }) => intl.formatMessage({ id: s }, options?.values);

describe('buildProcedureUsage', () => {
  it('counts a procedure once on each technique it implements', () => {
    const usage = buildProcedureUsage([{ id: 'p1', name: 'P1', techniqueIds: ['ap1', 'ap2'] }, { id: 'p2', name: 'P2', techniqueIds: ['ap1'] }]);
    expect(usage.get('ap1')?.score).toBe(2);
    expect(usage.get('ap2')?.score).toBe(1);
  });
  it('counts a procedure listed twice once', () => {
    const p = { id: 'p1', name: 'P1', techniqueIds: ['ap1'] };
    expect(buildProcedureUsage([p, p]).get('ap1')?.score).toBe(1);
  });
  it('ignores procedures without techniques', () => {
    expect(buildProcedureUsage([{ id: 'p1', name: 'P1', techniqueIds: [] }]).size).toBe(0);
  });
  it('lists the procedures of a technique by name', () => {
    const usage = buildProcedureUsage([{ id: 'p2', name: 'Zeta', techniqueIds: ['ap1'] }, { id: 'p1', name: 'Alpha', techniqueIds: ['ap1'] }]);
    expect(usage.get('ap1')?.linkedEntities).toEqual([
      { id: 'p1', name: 'Alpha', entity_type: 'Procedure' },
      { id: 'p2', name: 'Zeta', entity_type: 'Procedure' },
    ]);
  });
});

describe('buildProcedureCellDecorations', () => {
  // T1 has 4 procedures (the max); T2 has none but its sub-technique T2.1 has 1; T3 is used with no procedures; T4 is neither.
  const t21: HeatTechniqueNode = { attack_pattern_id: 't2.1', name: 'Technique 2.1', x_mitre_id: 'T0002.001' };
  const techniques: HeatTechniqueNode[] = [
    { attack_pattern_id: 't1', name: 'Technique 1', x_mitre_id: 'T0001' },
    { attack_pattern_id: 't2', name: 'Technique 2', x_mitre_id: 'T0002', subAttackPatterns: [t21] },
    { attack_pattern_id: 't3', name: 'Technique 3', x_mitre_id: 'T0003' },
    { attack_pattern_id: 't4', name: 'Technique 4', x_mitre_id: 'T0004' },
  ];
  const usage = buildProcedureUsage([
    { id: 'p1', name: 'P1', techniqueIds: ['t1', 't2.1'] },
    { id: 'p2', name: 'P2', techniqueIds: ['t1'] },
    { id: 'p3', name: 'P3', techniqueIds: ['t1'] },
    { id: 'p4', name: 'P4', techniqueIds: ['t1'] },
  ]);
  const scale = computeHeatScale(usage, heatmapTechniqueIds(techniques));
  const decorations = buildProcedureCellDecorations({ usage, scale, techniques, usedIds: new Set(['t1', 't3']), t });

  it('reads the maximum from the counted techniques', () => {
    expect(scale.max).toBe(4);
  });
  it('fills a technique from its own count with dark text', () => {
    expect(decorations.get('t1')).toMatchObject({ fill: heatFill(4), textTone: 'dark' });
  });
  it('gives a parent with only sub-technique counts a border, never a fill', () => {
    expect(decorations.get('t2')).toMatchObject({ border: heatBorder(0) });
    expect(decorations.get('t2')?.fill).toBeUndefined();
    expect(decorations.get('t2.1')).toMatchObject({ fill: heatFill(0) });
  });
  it('gives a used technique without procedures a neutral border', () => {
    expect(decorations.get('t3')).toMatchObject({ border: 'var(--border-elevation-default)' });
  });
  it('does not decorate a technique that is neither used nor counted', () => {
    expect(decorations.has('t4')).toBe(false);
  });
  it('does not let a technique hidden by the filter set the maximum', () => {
    const hiddenUsage = buildProcedureUsage([{ id: 'p1', name: 'P1', techniqueIds: ['hidden'] }, { id: 'p2', name: 'P2', techniqueIds: ['hidden', 't1'] }]);
    expect(computeHeatScale(hiddenUsage, heatmapTechniqueIds([{ attack_pattern_id: 't1', name: 'T1' }])).max).toBe(1);
  });
  it('includes sub-techniques in the scale input', () => {
    expect(heatmapTechniqueIds([{ attack_pattern_id: 't2', name: 'T2', subAttackPatterns: [{ attack_pattern_id: 't2.1', name: 'T2.1' }] }])).toEqual(new Set(['t2', 't2.1']));
  });
  it('names the cell with its procedure count', () => {
    expect(decorations.get('t1')?.accessibleName).toBe('T0001 - Technique 1, 4 procedures');
    expect(decorations.get('t2.1')?.accessibleName).toBe('T0002.001 - Technique 2.1, 1 procedure');
  });
  it('decorates nothing for an entity without procedures except its used techniques', () => {
    const empty = buildProcedureUsage([]);
    const emptyScale = computeHeatScale(empty, heatmapTechniqueIds(techniques));
    const none = buildProcedureCellDecorations({ usage: empty, scale: emptyScale, techniques, usedIds: new Set(['t1']), t });
    expect(emptyScale.max).toBe(0);
    expect([...none.keys()]).toEqual(['t1']);
    expect(none.get('t1')?.fill).toBeUndefined();
  });
});
