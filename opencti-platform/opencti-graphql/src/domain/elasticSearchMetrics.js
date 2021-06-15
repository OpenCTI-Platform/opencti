import { getStats } from '../database/elasticSearch';

// eslint-disable-next-line
export const getMetrics = async () => {
  return getStats();
};
