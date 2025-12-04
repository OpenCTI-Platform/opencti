import { getMainRepresentative } from '../../../../../utils/defaultRepresentatives';
import * as R from 'ramda';
import { useFormatter } from '../../../../../components/i18n';

export const useStixRelationshipsMultiHorizontalBars = (
  subSelection,
  stixRelationshipsDistribution,
  finalSubDistributionField,
  finalField
) => {
  const { t_i18n } = useFormatter();
  const distributionKey =
    subSelection.perspective === 'entities'
      ? 'stixCoreObjectsDistribution'
      : 'stixCoreRelationshipsDistribution';

  const categories = stixRelationshipsDistribution.map((n) =>
    getMainRepresentative(n.entity, t_i18n('Restricted'))
  );
  const entitiesMapping = {};
  const getDistributionKey = (distribution) => {
    let distributionKey;
    if (finalSubDistributionField === 'internal_id') {
      distributionKey = getMainRepresentative(
        distribution.entity,
        t_i18n('Restricted')
      );
    } else if (distribution.entity) {
      distributionKey = distribution.entity.representative
        ? getMainRepresentative(distribution.entity, t_i18n('Restricted'))
        : distribution.entity.name
          ? distribution.entity.name
          : distribution.entity.label
            ? distribution.entity.label
            : distribution.label;
    } else {
      distributionKey = distribution.label;
    }
    return distributionKey;
  };
  for (const distrib of stixRelationshipsDistribution) {
    for (const subDistrib of distrib.entity[distributionKey]) {
      const subDistributionKey = getDistributionKey(subDistrib);
      entitiesMapping[subDistributionKey] =
        (entitiesMapping[subDistributionKey] || 0) + subDistrib.value;
    }
  }
  const sortedEntityMapping = R.take(
    subSelection.number ?? 15,
    Object.entries(entitiesMapping).sort(([, a], [, b]) => b - a)
  );
  const categoriesValues = {};
  for (const distrib of stixRelationshipsDistribution) {
    for (const sortedEntity of sortedEntityMapping) {
      const entityData = R.head(
        distrib.entity?.[distributionKey].filter(
          (entityDistrib) =>
            getDistributionKey(entityDistrib) === sortedEntity[0]
        )
      );
      let value = 0;
      if (entityData) {
        value = entityData.value;
      }
      if (categoriesValues[getMainRepresentative(distrib.entity)]) {
        categoriesValues[getMainRepresentative(distrib.entity)].push(value);
      } else {
        categoriesValues[getMainRepresentative(distrib.entity)] = [value];
      }
    }
    const sum = (
      categoriesValues[getMainRepresentative(distrib.entity)] || []
    ).reduce((partialSum, a) => partialSum + a, 0);
    if (categoriesValues[getMainRepresentative(distrib.entity)]) {
      categoriesValues[getMainRepresentative(distrib.entity)].push(
        distrib.value - sum
      );
    } else {
      categoriesValues[getMainRepresentative(distrib.entity)] = [
        distrib.value - sum,
      ];
    }
  }
  sortedEntityMapping.push(['Others', 0]);
  const chartData = sortedEntityMapping
    .map((sortedEntity, index) => {
      return {
        name: sortedEntity[0],
        data: Object.entries(categoriesValues).map(
          (category) => category[1][index]
        ),
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
    subSectionIdsOrder = R.take(
      subSelection.number ?? 15,
      Object.entries(subSectionIdsOrder)
        .sort(([, a], [, b]) => b - a)
        .map((k) => k[0])
    );
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
