import type { AuthContext, AuthUser } from '../../types/user';
import { addUser, findAll as findAllUser } from '../../domain/user';
import { SYSTEM_USER } from '../../utils/access';
import type { BasicGroupEntity, BasicStoreCommon } from '../../types/store';
import { findDefaultIngestionGroups } from '../../domain/group';
import { FunctionalError, ValidationError } from '../../config/errors';
import type { UserAddInput } from '../../generated/graphql';

export const userAlreadyExists = async (context: AuthContext, name: string) => {
  // We use SYSTEM_USER because manage ingestion should be enough to create an ingestion Feed
  const users = await findAllUser(context, SYSTEM_USER, {
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['name'],
          values: [name],
        },
      ],
      filterGroups: [],
    },
    connectionFormat: false
  }) as BasicStoreCommon[];
  return users.length > 0;
};

export const createOnTheFlyUser = async (context: AuthContext, user: AuthUser, input: { userName: string, confidenceLevel: string | null | undefined }) => {
  const defaultIngestionGroups: BasicGroupEntity[] = await findDefaultIngestionGroups(context, user) as BasicGroupEntity[];
  if (defaultIngestionGroups.length < 1) {
    throw FunctionalError('You have not defined a default group for ingestion users', {});
  }
  const isUserAlreadyExisting = await userAlreadyExists(context, input.userName);
  if (isUserAlreadyExisting) {
    throw FunctionalError('This service account already exists. Change the instance name to change the automatically created service account name', {});
  }
  let userInput: UserAddInput;
  userInput = {
    name: input.userName,
    prevent_default_groups: true,
    groups: [defaultIngestionGroups[0].id],
    user_service_account: true,
  };
  if (input.confidenceLevel) {
    const userConfidence = parseFloat(input.confidenceLevel);
    if (userConfidence < 0 || userConfidence > 100 || !Number.isInteger(userConfidence)) {
      throw ValidationError('The confidence_level should be an integer between 0 and 100', 'confidence_level');
    }
    userInput = { ...userInput, user_confidence_level: { max_confidence: userConfidence, overrides: [] } };
  }
  const newlyCreatedUser = await addUser(context, user, userInput);
  return newlyCreatedUser;
};
