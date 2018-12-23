import { getSettings, updateSettings } from '../domain/settings';
import { admin, auth } from './wrapper';

const settingsResolvers = {
  Query: {
    settings: auth(() => getSettings())
  },
  Mutation: {
    settingsUpdate: admin((_, { id, input }, { user }) =>
      updateSettings(user, id, input)
    )
  }
};

export default settingsResolvers;
