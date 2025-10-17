export const getEntityMetricsConfiguration = () => {
  // TODO take from yaml/env
  return [{ entity_type: 'Organization', metrics: ['number_of_validated_reports'] }];
};

export const getMetricsNames = () => {
  return ['number_of_validated_reports'];
};

export const isMetricsName = (key: string) => {
  return getMetricsNames().includes(key);
};
