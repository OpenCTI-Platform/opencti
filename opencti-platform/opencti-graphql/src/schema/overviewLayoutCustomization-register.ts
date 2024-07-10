import { schemaOverviewLayoutCustomization } from './schema-overviewLayoutCustomization';

export const registerEntityOverviewLayoutCustomization = (type: string, overviewLayoutCustomization: Array<{ key: string, values: { width: number } }>) => {
  schemaOverviewLayoutCustomization.set(type, (overviewLayoutCustomization ?? []));
};
