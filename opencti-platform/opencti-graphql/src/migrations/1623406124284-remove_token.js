import { v4 as uuid } from 'uuid';
import { findAllPaginated } from '../domain/user';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { deleteElementById, patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { listAllFromEntitiesThroughRelations } from '../database/middleware-loader';

export const up = async (next) => {
  // For each user, get default token and patch the user to add a bearer
  // Delete all tokens and relations to it
  const context = executionContext('migration');
  const connection = await findAllPaginated(context, SYSTEM_USER);
  for (let index = 0; index < connection.edges.length; index += 1) {
    const user = connection.edges[index].node;
    const userToken = await listAllFromEntitiesThroughRelations(context, SYSTEM_USER, user.id, 'authorized-by', 'Token', { withInferences: false });
    if (userToken) {
      // Update the token of the client with existing  token
      const patch = { api_token: userToken.uuid };
      await patchAttribute(context, SYSTEM_USER, user.id, ENTITY_TYPE_USER, patch);
      // Remove token
      await deleteElementById(context, SYSTEM_USER, userToken.id, 'Token');
    } else {
      // No token found, just create a new uuid
      const patch = { api_token: uuid() };
      await patchAttribute(context, SYSTEM_USER, user.id, ENTITY_TYPE_USER, patch);
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
