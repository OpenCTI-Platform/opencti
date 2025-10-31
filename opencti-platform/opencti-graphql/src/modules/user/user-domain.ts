import { v4 as uuid } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { addUser, findUserPaginated } from '../../domain/user';
import { SYSTEM_USER } from '../../utils/access';
import type { BasicGroupEntity } from '../../types/store';
import { findDefaultIngestionGroups } from '../../domain/group';
import { FunctionalError, ValidationError } from '../../config/errors';
import type { UserAddInput } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';

export const userAlreadyExists = async (context: AuthContext, name: string) => {
  // We use SYSTEM_USER because manage ingestion should be enough to create an ingestion Feed
  const users = await findUserPaginated(context, SYSTEM_USER, {
    first: 1,
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['name'],
          values: [name],
        },
      ],
      filterGroups: [],
    }
  });
  return users.edges.length > 0;
};

export const createOnTheFlyUser = async (
  context: AuthContext,
  user: AuthUser,
  input: { userName: string, serviceAccount: boolean, confidenceLevel: number | null | undefined }
) => {
  const defaultIngestionGroups: BasicGroupEntity[] = await findDefaultIngestionGroups(context, user) as BasicGroupEntity[];
  if (defaultIngestionGroups.length < 1) {
    throw FunctionalError('You have not defined a default group for ingestion users', {});
  }
  const isUserAlreadyExisting = await userAlreadyExists(context, input.userName);
  if (isUserAlreadyExisting) {
    if (input.serviceAccount) {
      throw FunctionalError('This service account already exists. Change the instance name to change the automatically created service account name', { name: input.userName });
    }
    throw FunctionalError('This user already exists. Change the feed\'s name to change the automatically created user\'s name', { name: input.userName });
  }
  const { platform_organization } = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);

  let userInput: UserAddInput = {
    password: uuid(),
    user_email: `automatic+${uuid()}@opencti.invalid`,
    name: input.userName,
    prevent_default_groups: true,
    groups: [defaultIngestionGroups[0].id],
    objectOrganization: platform_organization && !input.serviceAccount ? [platform_organization] : [],
    user_service_account: input.serviceAccount,
  };

  if (input.confidenceLevel) {
    const userConfidence = input.confidenceLevel;
    if (userConfidence < 0 || userConfidence > 100 || !Number.isInteger(userConfidence)) {
      throw ValidationError('The confidence_level should be an integer between 0 and 100', 'confidence_level');
    }
    userInput = { ...userInput, user_confidence_level: { max_confidence: userConfidence, overrides: [] } };
  }
  const newlyCreatedUser = await addUser(context, user, userInput);
  return newlyCreatedUser;
};
