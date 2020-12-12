import { loadById } from '../database/middleware';
import { ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../schema/general';

// eslint-disable-next-line import/prefer-default-export
export const findById = async (id) => {
  let data = await loadById(id, ABSTRACT_STIX_OBJECT);
  if (!data) {
    data = await loadById(id, ABSTRACT_STIX_RELATIONSHIP);
  }
  return data;
};
