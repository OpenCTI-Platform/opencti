export type MatrixVariant = 'default' | 'investigation';

export interface MatrixTechniqueLike {
  name: string;
  x_mitre_id?: string | null;
}

export interface MatrixConfig {
  formatLabel: (ap: MatrixTechniqueLike) => string;
  compareTechniques: (a: MatrixTechniqueLike, b: MatrixTechniqueLike) => number;
  badgeColors?: { color: string; textColor: string };
  canAdd: boolean;
  keyboardCells: boolean;
  // When false, sub-techniques keep the order the API returns.
  sortSubTechniques: boolean;
}

const MITRE_ID_REGEX = /^T(\d+)(?:\.(\d+))?$/i;

// Returns [main, sub] for a technique ID such as T1074 or T1074.001, or null when not a T-ID.
// A missing sub number counts as -1 so a parent sorts before its sub-techniques.
const parseMitreId = (id?: string | null): [number, number] | null => {
  const match = id ? MITRE_ID_REGEX.exec(id) : null;
  if (!match) return null;
  return [Number(match[1]), match[2] === undefined ? -1 : Number(match[2])];
};

export const compareByMitreId = (a: MatrixTechniqueLike, b: MatrixTechniqueLike): number => {
  const idA = parseMitreId(a.x_mitre_id);
  const idB = parseMitreId(b.x_mitre_id);
  if (idA && !idB) return -1;
  if (!idA && idB) return 1;
  if (idA && idB) {
    if (idA[0] !== idB[0]) return idA[0] - idB[0];
    if (idA[1] !== idB[1]) return idA[1] - idB[1];
  }
  return a.name.localeCompare(b.name);
};

const defaultConfig = (isCoverage: boolean): MatrixConfig => ({
  formatLabel: (ap) => ap.name,
  compareTechniques: (a, b) => a.name.localeCompare(b.name),
  badgeColors: undefined,
  canAdd: !isCoverage,
  keyboardCells: false,
  sortSubTechniques: false,
});

const investigationConfig: MatrixConfig = {
  formatLabel: (ap) => (ap.x_mitre_id ? `${ap.x_mitre_id} - ${ap.name}` : ap.name),
  compareTechniques: compareByMitreId,
  // FDS-WORKAROUND #70: --black-800 is not compiled into dist/index.css — see fds-migration/LIBRARY-FEEDBACK.md #70
  badgeColors: { color: 'var(--gray-800)', textColor: 'var(--gray-100)' },
  canAdd: false,
  keyboardCells: true,
  sortSubTechniques: true,
};

export const getMatrixConfig = (variant: MatrixVariant | undefined, isCoverage: boolean): MatrixConfig => {
  return variant === 'investigation' ? investigationConfig : defaultConfig(isCoverage);
};
