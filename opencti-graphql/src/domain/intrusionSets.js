import { deleteByID, loadAll, loadByID, now, qk } from '../database/grakn';

export const findAll = async (
  first = 25,
  after = undefined,
  orderBy = 'name',
  orderMode = 'asc'
) => loadAll('Intrusion-Set', first, after, orderBy, orderMode);

export const findById = intrusionSetId => loadByID(intrusionSetId);

export const addIntrusionSet = async intrusionSet => {
  const createIntrusionSet = qk(`insert $intrusionSet isa Intrusion-Set 
    has type "intrusion-set";
    $intrusionSet has name "${intrusionSet.name}";
    $intrusionSet has description "${intrusionSet.description}";
    $intrusionSet has alias "${intrusionSet.alias}";
    $intrusionSet has created ${now()};
    $intrusionSet has stix_id "${intrusionSet.stix_id}";
    $intrusionSet has stix_label "${intrusionSet.stix_label}";
    $intrusionSet has revoked false;
  `);
  return createIntrusionSet.then(result => findById(result.data.intrusion.id));
};

export const deleteIntrusionSet = intrusionSetId => deleteByID(intrusionSetId);
