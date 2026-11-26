import type { ModuleDescriptor } from '../module-descriptor';
import { TELEMETRY_MANAGER_DEFINITION } from '../../manager/telemetryManager';
import { PLATFORM_USAGE_METRICS_MANAGER_DEFINITION } from '../../manager/platformUsageMetricsManager';

const telemetryModule: ModuleDescriptor = {
  id: 'telemetry',
  managers: [TELEMETRY_MANAGER_DEFINITION, PLATFORM_USAGE_METRICS_MANAGER_DEFINITION],
};

export default telemetryModule;
