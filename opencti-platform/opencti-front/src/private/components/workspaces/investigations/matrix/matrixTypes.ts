import type { LinkedEntity } from '@components/techniques/attack_patterns/attack_patterns_matrix/attackPatternsMatrixCellDecoration';

export interface TechniqueUsage {
  attackPatternId: string;
  score: number;
  linkedEntities: LinkedEntity[];
}

export interface HeatScale {
  max: number; // min is always 1
}
