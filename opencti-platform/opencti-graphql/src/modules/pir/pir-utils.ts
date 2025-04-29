import type { BasicStoreEntityPIR } from './pir-types';

export const computePirScore = (pir: BasicStoreEntityPIR, dependencies: number) => {
  const maxScore = pir.pirCriteria.reduce((acc, val) => acc + val.weight, 0);
  if (maxScore <= 0) return 0;
  return Math.round((dependencies / maxScore) * 100);
};
