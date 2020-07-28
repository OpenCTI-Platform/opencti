import { loadById } from '../database/grakn';
import { ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../utils/idGenerator';

export const findById = async (id) => {
  let data = await loadById(id, ABSTRACT_STIX_OBJECT);
  if (!data) {
    data = await loadById(id, ABSTRACT_STIX_RELATIONSHIP);
  }
  return data;
};
