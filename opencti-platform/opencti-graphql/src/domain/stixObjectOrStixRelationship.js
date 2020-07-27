import { loadById } from '../database/grakn';
import { ForbiddenAccess } from '../config/errors';
import { isStixObject, isStixRelationship } from '../utils/idGenerator';

export const findById = async (id) => {
  const data = await loadById(id);
  if (!data) return data;
  if (!isStixObject(data.type)) throw ForbiddenAccess();
  if (!isStixRelationship(data.type)) throw ForbiddenAccess();
  return data;
};
