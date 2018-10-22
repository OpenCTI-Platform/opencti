import ApplicationError from './ApplicationError';

export default class DatabaseError extends ApplicationError {
  constructor(neo4jError) {
    super(neo4jError.code);
  }
}
