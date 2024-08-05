import { schemaOverviewLayoutCustomization } from './schema-overviewLayoutCustomization';
import type { OverviewLayoutCustomization } from '../modules/entitySetting/entitySetting-types';

export const registerEntityOverviewLayoutCustomization = (type: string, overviewLayoutCustomization: Array<OverviewLayoutCustomization>) => {
  schemaOverviewLayoutCustomization.set(type, (overviewLayoutCustomization ?? []));
};
