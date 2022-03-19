import { getStats } from '../database/engine';

// eslint-disable-next-line
export const getMetrics = async () => {
  return getStats();
};
