import { getMatrixConfig } from '../../../techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixConfig';
import { heatBorder, heatFill, heatStopIndex } from './heatScale';
import type { CellDecoration, HeatScale, LinkedEntity, TechniqueUsage } from './matrixTypes';

export interface MatrixTechniqueNode {
  attack_pattern_id: string;
  name: string;
  x_mitre_id?: string | null;
  subAttackPatterns?: ReadonlyArray<MatrixTechniqueNode> | null;
}

type Translate = (s: string, options?: { values?: Record<string, string | number> }) => string;

const NEUTRAL_BORDER = 'var(--border-elevation-default)';

const { formatLabel } = getMatrixConfig('investigation', false);

const byName = (a: LinkedEntity, b: LinkedEntity) => a.name.localeCompare(b.name);

// Entities of the given techniques, each once (by id), sorted by name.
const mergeEntities = (usages: (TechniqueUsage | undefined)[]): LinkedEntity[] => {
  const merged = new Map<string, LinkedEntity>();
  usages.forEach((technique) => {
    technique?.linkedEntities.forEach((entity) => {
      if (!merged.has(entity.id)) merged.set(entity.id, entity);
    });
  });
  return Array.from(merged.values()).sort(byName);
};

// Applies the PRD cell rules (spec section 3). A technique with no entry renders as a standard cell.
export const buildCellDecorations = ({ usage, scale, techniques, investigationIds, heatmapOn, t }: {
  usage: Map<string, TechniqueUsage>;
  scale: HeatScale;
  techniques: ReadonlyArray<MatrixTechniqueNode>;
  investigationIds: Set<string>;
  heatmapOn: boolean;
  t: Translate;
}): Map<string, CellDecoration> => {
  const decorations = new Map<string, CellDecoration>();

  const describe = (technique: MatrixTechniqueNode, subTechniques: ReadonlyArray<MatrixTechniqueNode>) => {
    const own = usage.get(technique.attack_pattern_id);
    const ownScore = own?.score ?? 0;
    const maxSubScore = subTechniques.reduce((max, sub) => Math.max(max, usage.get(sub.attack_pattern_id)?.score ?? 0), 0);
    const present = investigationIds.has(technique.attack_pattern_id) || ownScore > 0;
    // Only a heat border can reveal a parent that is not itself in the investigation.
    const bordersFromSubs = heatmapOn && ownScore === 0 && maxSubScore > 0;
    if (!present && !bordersFromSubs) return;

    const linkedEntities = mergeEntities([own, ...subTechniques.map((sub) => usage.get(sub.attack_pattern_id))]);
    const decoration: CellDecoration = {
      linkedEntities,
      accessibleName: t('{label}, linked to {count, plural, one {# entity} other {# entities}}', {
        values: { label: formatLabel(technique), count: linkedEntities.length },
      }),
    };
    if (heatmapOn) {
      if (ownScore > 0) {
        decoration.fill = heatFill(heatStopIndex(ownScore, scale));
        decoration.textTone = 'dark';
      } else if (maxSubScore > 0) {
        decoration.border = heatBorder(heatStopIndex(maxSubScore, scale));
      } else {
        decoration.border = NEUTRAL_BORDER;
      }
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
