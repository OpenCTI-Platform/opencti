import { deleteElementById, internalLoadById } from '../database/middleware';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { FunctionalError, UnsupportedError } from '../config/errors';

// eslint-disable-next-line import/prefer-default-export
export const stixDelete = async (user, id) => {
  const element = await internalLoadById(user, id);
  if (element) {
    if (isStixObject(element.entity_type) || isStixRelationship(element.entity_type)) {
      return deleteElementById(user, element.id, element.entity_type);
    }
    throw UnsupportedError('This method can only delete Stix element');
  }
  throw FunctionalError(`Cannot delete the stix element, ${id} cannot be found.`);
};
