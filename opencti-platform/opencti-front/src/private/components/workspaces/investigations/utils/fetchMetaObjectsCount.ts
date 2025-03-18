import { fetchQuery } from '../../../../../relay/environment';
import { InvestigationGraphStixCountRelToQuery$data } from '../__generated__/InvestigationGraphStixCountRelToQuery.graphql';
import { investigationGraphCountRelToQuery } from '../InvestigationGraph';
import { ObjectToParse } from '../../../../../utils/graph/utils/useGraphParser';

const fetchMetaObjectsCount = async (objects: ObjectToParse[]) => {
  // Keep only meta-objects and identities.
  const objectIds = objects.filter(
    (object) => object.parent_types.includes('Stix-Meta-Object')
      || object.parent_types.includes('Identity'),
  ).map((object) => object.id);

  let objectsWithCount = [...objects];
  if (objectIds.length > 0) {
    const { stixRelationshipsDistribution: relCounts } = await fetchQuery(
      investigationGraphCountRelToQuery,
      { objectIds },
    ).toPromise() as InvestigationGraphStixCountRelToQuery$data;

    // For each object, add the number of relations it has in our objects data.
    (relCounts ?? []).forEach((count) => {
      if (!count) return;
      const { label, value } = count;
      const object = objects.find((obj) => obj.id === label);
      if (object) {
        objectsWithCount = [
          ...objectsWithCount.filter((obj) => obj.id !== label),
          {
            ...object,
            numberOfConnectedElement: value ?? undefined,
          },
        ];
      }
    });
  }
  return objectsWithCount;
};

export default fetchMetaObjectsCount;
