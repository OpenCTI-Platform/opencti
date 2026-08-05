import { getStats } from '../database/engine';

export const getMetrics = async () => {
  return getStats();
};
