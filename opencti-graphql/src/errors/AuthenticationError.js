import ApplicationError from './ApplicationError';

export default class AuthenticationError extends ApplicationError {
  constructor() {
    super('login failed');
    this.status = 401;
  }
}
