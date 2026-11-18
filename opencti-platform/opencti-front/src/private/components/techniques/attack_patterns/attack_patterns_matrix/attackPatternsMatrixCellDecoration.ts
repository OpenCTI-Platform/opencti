// What a matrix screen can draw on a technique cell, on top of the default styles.
// The shared matrix owns this contract; a screen such as the investigation heatmap only fills it in.

export interface LinkedEntity {
  id: string;
  name: string;
  entity_type: string;
}

export interface CellDecoration {
  fill?: string;
  border?: string;
  textTone?: 'dark' | 'default';
  linkedEntities: LinkedEntity[];
  accessibleName: string;
}

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

// Lists at most `max` names, then "and N more".
export const formatNameList = (names: string[], max: number, t: Translate): string => {
  const shown = names.slice(0, max).join(', ');
  const rest = names.length - max;
  return rest > 0 ? `${shown} ${t('and {count} more', { values: { count: rest } })}` : shown;
};
