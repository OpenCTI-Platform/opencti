type HalfWidth = 6;
type FullWidth = 12;
export type OverviewLayoutCustomizationSettingsConfigurationWidth = HalfWidth | FullWidth;
export interface OverviewLayoutCustomizationSettingsConfigurationParameters {
  order: number;
  width: OverviewLayoutCustomizationSettingsConfigurationWidth;
}
export type OverviewLayoutCustomizationSettingsConfigurationWidgets = Map<string, OverviewLayoutCustomizationSettingsConfigurationParameters>;
export type OverviewLayoutCustomization = Map<string, OverviewLayoutCustomizationSettingsConfigurationWidgets>;

const threatActorIndividualConfiguration = new Map<string, OverviewLayoutCustomizationSettingsConfigurationParameters>();
threatActorIndividualConfiguration.set('details', { order: 1, width: 6 });
threatActorIndividualConfiguration.set('basicInformation', { order: 2, width: 6 });
threatActorIndividualConfiguration.set('demographics-biographics', { order: 3, width: 6 });
threatActorIndividualConfiguration.set('latestCreatedRelationships', { order: 5, width: 6 });
threatActorIndividualConfiguration.set('latestContainers', { order: 6, width: 6 });
threatActorIndividualConfiguration.set('externalReferences', { order: 7, width: 6 });
threatActorIndividualConfiguration.set('mostRecentHistory', { order: 8, width: 6 });
threatActorIndividualConfiguration.set('notes', { order: 9, width: 12 });

export const defaultConfiguration = new Map<string, OverviewLayoutCustomizationSettingsConfigurationParameters>();
defaultConfiguration.set('details', { order: 1, width: 6 });
defaultConfiguration.set('basicInformation', { order: 2, width: 6 });
defaultConfiguration.set('latestCreatedRelationships', { order: 5, width: 6 });
defaultConfiguration.set('latestContainers', { order: 6, width: 6 });
defaultConfiguration.set('externalReferences', { order: 7, width: 6 });
defaultConfiguration.set('mostRecentHistory', { order: 8, width: 6 });
defaultConfiguration.set('notes', { order: 9, width: 12 });

export const overviewLayoutCustomization: OverviewLayoutCustomization = new Map<string, OverviewLayoutCustomizationSettingsConfigurationWidgets>();
overviewLayoutCustomization.set(
  'Threat-Actor-Individual',
  threatActorIndividualConfiguration,
);
