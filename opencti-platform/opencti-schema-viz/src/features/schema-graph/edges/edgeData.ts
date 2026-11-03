import type { EdgeRelation } from '../buildVisibleGraph';

export type EdgeEmphasis = 'normal' | 'highlighted' | 'dimmed';

export interface InheritanceEdgeData {
  indirect: boolean;
  emphasis: EdgeEmphasis;
}

export interface RelationEdgeData {
  relations: EdgeRelation[];
  tone: 'relationship' | 'ref';
  label: string;
  description: string;
  emphasis: EdgeEmphasis;
  parallel: boolean;
}

export const MARKER_IDS = {
  inheritance: 'sv-marker-inheritance',
  relationship: 'sv-marker-relationship',
  ref: 'sv-marker-ref',
  highlighted: 'sv-marker-highlighted',
} as const;
