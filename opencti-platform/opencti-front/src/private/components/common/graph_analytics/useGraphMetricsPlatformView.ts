import useAuth from '../../../../utils/hooks/useAuth';

export const GRAPH_METRICS_SORT_KEYS = ['graph_degree', 'graph_betweenness', 'graph_cluster_size'];

export const isGraphMetricsSortKey = (key: string | null | undefined) => !!key && GRAPH_METRICS_SORT_KEYS.includes(key);

/**
 * The stored graph metrics count every relationship of the platform: sorting and filtering on them is reserved to
 * users reading all relationships, and the backend only offers them the graph degree filter key.
 */
const useGraphMetricsPlatformView = () => {
  const { filterKeysSchema } = useAuth().schema;
  return filterKeysSchema.get('Stix-Core-Object')?.has('graph_degree') ?? false;
};

export default useGraphMetricsPlatformView;
