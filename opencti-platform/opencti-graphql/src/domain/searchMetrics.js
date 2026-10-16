import { getStats, getIndexStats } from '../database/engine';

// eslint-disable-next-line
export const getMetrics = async () => {
  return getStats();
};

export const getIndexMetrics = async () => {
  return getIndexStats();
};
