export interface LinkedEntity {
  id: string;
  name: string;
  entity_type: string;
}

export interface TechniqueUsage {
  attackPatternId: string;
  score: number;
  linkedEntities: LinkedEntity[];
}

export interface HeatScale {
  max: number; // min is always 1
}

export interface CellDecoration {
  fill?: string;
  border?: string;
  textTone?: 'dark' | 'default';
  linkedEntities: LinkedEntity[];
  accessibleName: string;
}
