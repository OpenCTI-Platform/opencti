export default class ApplicationError extends Error {
  constructor(message) {
    super();
    this.message = message;
    this.name = this.constructor.name;
    this.status = 500;
    Error.captureStackTrace(this, this.constructor);
  }
}
