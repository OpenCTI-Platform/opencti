export type OverviewLayoutCustomizationSettingsConfigurationWidgets = Map<string, number>;
export type OverviewLayoutCustomization = Map<string, OverviewLayoutCustomizationSettingsConfigurationWidgets>;

export const defaultConfiguration = new Map<string, number>();
defaultConfiguration.set('details', 6);
defaultConfiguration.set('basicInformation', 6);
defaultConfiguration.set('demographics', 6);
defaultConfiguration.set('biographics', 6);
defaultConfiguration.set('latestCreatedRelationships', 6);
defaultConfiguration.set('latestContainers', 6);
defaultConfiguration.set('externalReferences', 6);
defaultConfiguration.set('mostRecentHistory', 6);
defaultConfiguration.set('notes', 12);
