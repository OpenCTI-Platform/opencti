import type { AuthContext } from '../../../types/user';
import { logApp } from '../../../config/conf';

export const fakeFixForPoc = async (_context: AuthContext) => {
  logApp.info('fakeFixForPoc execution');
  return {
    message: 'This is a fake fix for proof of concept purposes.',
  };
};
