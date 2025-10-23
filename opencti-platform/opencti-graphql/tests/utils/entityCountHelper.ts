export const entitiesCounter: Record<string, number> = {};
entitiesCounter.capability = 51;
entitiesCounter.entitySetting = 45;
entitiesCounter.label = 13;
entitiesCounter.statusTemplate = 8;
entitiesCounter.externalReference = 7;

export const entitiesCounterTotal = Object.values(entitiesCounter).reduce((acc, value) => acc + value, 0);

export const relationsCounter: Record<string, number> = {};
relationsCounter['has-capability'] = 63;
