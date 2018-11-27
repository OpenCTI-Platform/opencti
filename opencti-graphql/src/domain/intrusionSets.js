import { deleteByID, loadAll, loadByID, now, qk } from '../database/grakn';

export const findAll = (first, after) => loadAll('Intrusion-Set', first, after);

export const findById = intrusionSetId => loadByID(intrusionSetId);

export const addIntrusionSet = async intrusionSet => {
  const createIntrusionSet = qk(`insert $intrusion isa Intrusion-Set 
    has type "intrusion-set";
    $intrusion has name "${intrusionSet.name}";
    $intrusion has description "${intrusionSet.description}";
    $intrusion has alias "${intrusionSet.alias}";
    $intrusion has created ${now()};
    $intrusion has stix_id "${intrusionSet.stix_id}";
    $intrusion has stix_label "${intrusionSet.stix_label}";
    $intrusion has revoked false;
  `);
  return createIntrusionSet.then(result => findById(result.data.intrusion.id));
};

export const deleteIntrusionSet = intrusionSetId => deleteByID(intrusionSetId);
