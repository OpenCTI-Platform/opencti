import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import { useFormatter } from '../../../../../components/i18n';

export const useStixRelationshipsMultiHorizontalBars = (
  subSelection,
  stixRelationshipsDistribution,
  finalSubDistributionField,
  finalField
) => {
  const { t_i18n } = useFormatter();
  const DEFAULT_SUBSELECTION_NUMBER = 15;
  const subSelectionNumber = subSelection.number ?? DEFAULT_SUBSELECTION_NUMBER;
  const distributionKey =
    subSelection.perspective === 'entities'
      ? 'stixCoreObjectsDistribution'
      : 'stixCoreRelationshipsDistribution';

  const categories = stixRelationshipsDistribution.map((n) =>
    getMainRepresentative(n.entity, t_i18n('Restricted'))
  );

  const getDistributionKey = (distribution) => {
    if (finalSubDistributionField === 'internal_id'){
      return getMainRepresentative(distribution.entity, t_i18n('Restricted'));
    }

    if (!distribution.entity) {
      return distribution.label;
    }

    if (distribution.entity.representative) {
      return getMainRepresentative(distribution.entity, t_i18n('Restricted'));
    }

    return distribution.entity.name
      || distribution.entity.label
      || distribution.label;
  };

  const entitiesMapping = {};
  for (const distrib of stixRelationshipsDistribution) {
    for (const subDistrib of distrib.entity[distributionKey]) {
      const subDistributionKey = getDistributionKey(subDistrib);
      entitiesMapping[subDistributionKey] =
        (entitiesMapping[subDistributionKey] || 0) + subDistrib.value;
    }
  }

  const sortedEntityMapping = Object.entries(entitiesMapping)
    .sort(([, a], [, b]) => b - a)
    .slice(0, subSelectionNumber);

  const categoriesValues = {};
  for (const distrib of stixRelationshipsDistribution) {
    const distribMap = new Map(distrib.entity?.[distributionKey].map(entityDistrib => [
        getDistributionKey(entityDistrib),
        entityDistrib
      ])
    );

    for (const sortedEntity of sortedEntityMapping) {
      const entityData = distribMap.get(sortedEntity[0]);
      const value = entityData?.value ?? 0;
      const mainRepresentative = getMainRepresentative(distrib.entity);

      if (categoriesValues[mainRepresentative]) {
        categoriesValues[mainRepresentative].push(value);
      } else {
        categoriesValues[mainRepresentative] = [value];
      }
    }

    const mainRepresentative = getMainRepresentative(distrib.entity);
    const sum = (categoriesValues[mainRepresentative] || []).reduce((partialSum, a) => partialSum + a, 0);

    (categoriesValues[mainRepresentative] ??= []).push(distrib.value - sum);
  }
  
  sortedEntityMapping.push(['Others', 0]);
  const chartData = sortedEntityMapping
    .map(([name], index) => {
      return {
        name,
        data: Object.values(categoriesValues).map((values) => values[index]),
      };
    })
    // To avoid displaying empty categories - especially for 'Others'
    .filter((entity) => entity.data.some((data) => data > 0));

  let subSectionIdsOrder = [];
  if (
    finalField === 'internal_id' &&
    finalSubDistributionField === 'internal_id'
  ) {
    // find subbars orders for entity subbars redirection
    for (const distrib of stixRelationshipsDistribution) {
      for (const subDistrib of distrib.entity[distributionKey]) {
        subSectionIdsOrder[subDistrib.label] =
          (subSectionIdsOrder[subDistrib.label] || 0) + subDistrib.value;
      }
    }
    subSectionIdsOrder = Object.entries(subSectionIdsOrder)
        .sort(([, a], [, b]) => b - a)
        .map((k) => k[0])
        .slice(0, subSelectionNumber);
  }

  const redirectionUtils =
    finalField === 'internal_id'
      ? stixRelationshipsDistribution.map((n) => ({
          id: n.label,
          entity_type: n.entity?.entity_type,
          series: subSectionIdsOrder.map((subSectionId) => {
            const [entity] =
              n.entity[distributionKey]?.filter(
                (e) => e.label === subSectionId
              ) ?? [];
            return {
              id: subSectionId,
              entity_type: entity ? entity.entity?.entity_type : null,
            };
          }),
        }))
      : null;
      
  return {
    chartData,
    redirectionUtils,
    categories,
  };
};
