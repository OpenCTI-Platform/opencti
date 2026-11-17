import { heatBorder, heatFill, heatStopIndex } from '../../../workspaces/investigations/matrix/heatScale';
import type { HeatScale, TechniqueUsage } from '../../../workspaces/investigations/matrix/matrixTypes';
import type { CellDecoration, LinkedEntity } from './attackPatternsMatrixCellDecoration';

export interface ProcedureWithTechniques {
  id: string;
  name: string;
  techniqueIds: ReadonlyArray<string>;
}

export interface HeatTechniqueNode {
  attack_pattern_id: string;
  name: string;
  x_mitre_id?: string | null;
  subAttackPatterns?: ReadonlyArray<HeatTechniqueNode> | null;
}

export type Translate = (s: string, options?: { values?: Record<string, string | number> }) => string;

const NEUTRAL_BORDER = 'var(--border-elevation-default)';

const byName = (a: LinkedEntity, b: LinkedEntity) => a.name.localeCompare(b.name);

// One entry per attack pattern: the procedures implementing it, each once, sorted by name. A procedure
// implementing two attack patterns counts once on each.
export const buildProcedureUsage = (procedures: ReadonlyArray<ProcedureWithTechniques>): Map<string, TechniqueUsage> => {
  const byTechnique = new Map<string, Map<string, LinkedEntity>>();
  procedures.forEach((procedure) => {
    procedure.techniqueIds.forEach((techniqueId) => {
      const linked = byTechnique.get(techniqueId) ?? new Map<string, LinkedEntity>();
      if (!linked.has(procedure.id)) linked.set(procedure.id, { id: procedure.id, name: procedure.name, entity_type: 'Procedure' });
      byTechnique.set(techniqueId, linked);
    });
  });
  const usage = new Map<string, TechniqueUsage>();
  byTechnique.forEach((linked, attackPatternId) => {
    const linkedEntities = Array.from(linked.values()).sort(byName);
    usage.set(attackPatternId, { attackPatternId, score: linkedEntities.length, linkedEntities });
  });
  return usage;
};

// The techniques shown and their sub-techniques: only they may set the heat scale maximum.
export const heatmapTechniqueIds = (techniques: ReadonlyArray<HeatTechniqueNode>): Set<string> => {
  const ids = new Set<string>();
  techniques.forEach((technique) => {
    ids.add(technique.attack_pattern_id);
    (technique.subAttackPatterns ?? []).forEach((sub) => ids.add(sub.attack_pattern_id));
  });
  return ids;
};

const formatLabel = (technique: HeatTechniqueNode) => (technique.x_mitre_id ? `${technique.x_mitre_id} - ${technique.name}` : technique.name);

// Same cell rules as the TTP analyser heatmap: a technique is filled from its own count only; a parent whose
// sub-techniques have counts, but which has none itself, gets a heat border from the highest sub-technique count;
// a used technique without procedures keeps a neutral border. Counts are never summed into the parent.
export const buildProcedureCellDecorations = ({ usage, scale, techniques, usedIds, t }: {
  usage: Map<string, TechniqueUsage>;
  scale: HeatScale;
  techniques: ReadonlyArray<HeatTechniqueNode>;
  usedIds: Set<string>;
  t: Translate;
}): Map<string, CellDecoration> => {
  const decorations = new Map<string, CellDecoration>();

  const describe = (technique: HeatTechniqueNode, subTechniques: ReadonlyArray<HeatTechniqueNode>) => {
    const own = usage.get(technique.attack_pattern_id);
    const ownScore = own?.score ?? 0;
    const maxSubScore = subTechniques.reduce((max, sub) => Math.max(max, usage.get(sub.attack_pattern_id)?.score ?? 0), 0);
    const present = usedIds.has(technique.attack_pattern_id) || ownScore > 0;
    const bordersFromSubs = ownScore === 0 && maxSubScore > 0;
    if (!present && !bordersFromSubs) return;

    const linkedEntities = own?.linkedEntities ?? [];
    const decoration: CellDecoration = {
      linkedEntities,
      accessibleName: t('{label}, {count, plural, one {# procedure} other {# procedures}}', {
        values: { label: formatLabel(technique), count: ownScore },
      }),
    };
    if (ownScore > 0) {
      decoration.fill = heatFill(heatStopIndex(ownScore, scale));
      decoration.textTone = 'dark';
    } else if (maxSubScore > 0) {
      decoration.border = heatBorder(heatStopIndex(maxSubScore, scale));
    } else {
      decoration.border = NEUTRAL_BORDER;
    }
    decorations.set(technique.attack_pattern_id, decoration);
  };

  techniques.forEach((technique) => {
    const subTechniques = technique.subAttackPatterns ?? [];
    describe(technique, subTechniques);
    subTechniques.forEach((sub) => describe(sub, []));
  });
  return decorations;
};
