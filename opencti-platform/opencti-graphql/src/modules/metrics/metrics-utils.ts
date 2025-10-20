import nconf from 'nconf';
import { UnsupportedError } from '../../config/errors';

let metricsConfiguration: EntityMetricConfiguration[];
const allAttributesFlat: string [] = [];

interface EntityMetricConfiguration {
  entity_type: string
  metrics: MetricDescription[]
}

interface MetricDescription {
  attribute: string
  name: string
  description?: string
}

export const loadEntityMetricsConfiguration = () => {
  metricsConfiguration = [];
  const metricsConfigurationEnv = nconf.get('app:schema_metrics');
  if (metricsConfigurationEnv) {
    // eslint-disable-next-line guard-for-in,no-restricted-syntax
    for (const metricKey in metricsConfigurationEnv) {
      const metricKeyNoCase = metricKey.toLowerCase();
      const metricListForCurrentEntity: MetricDescription[] = metricsConfigurationEnv[metricKey] as unknown as MetricDescription[];
      if (metricListForCurrentEntity) {
        if (metricListForCurrentEntity.length > 1) {
          throw UnsupportedError('Several metric per entity is not supported yet', { metricsEntity: metricKey });
        }
        if (metricListForCurrentEntity.length > 0) {
          const metricAttributes: MetricDescription = metricListForCurrentEntity[0] as unknown as MetricDescription;
          metricsConfiguration.push({ entity_type: `${metricKeyNoCase}`, metrics: [metricAttributes] });
          allAttributesFlat.push(metricAttributes.attribute);
        }
      }
    }
  }
};

export const getEntityMetricsConfiguration = () => {
  if (!metricsConfiguration) {
    loadEntityMetricsConfiguration();
  }
  return metricsConfiguration;
};

export const getMetricsAttributesNames = () => {
  if (!metricsConfiguration) {
    loadEntityMetricsConfiguration();
  }
  return allAttributesFlat;
};

export const isMetricsName = (key: string) => {
  if (!metricsConfiguration) {
    loadEntityMetricsConfiguration();
  }
  return getMetricsAttributesNames().includes(key);
};
