import ApplicationError from './ApplicationError';

export default class AuthenticationError extends ApplicationError {
  constructor() {
    super('Authentication required');
    this.status = 401;
  }
}
