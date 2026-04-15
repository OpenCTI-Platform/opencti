/*
 * Current rjsf schema validation required an client eval.
 * For this reason we needs to build our own.
 * For now, we will not validate the schema of notifier on frontend side
 * However the backend currently enforce the validation.
 */
const notifierValidator = {
  rawValidation: () => ({ errors: [], validationError: undefined }),
  validateFormData: () => ({ errors: [], errorSchema: {} }),
  isValid: () => true,
};

export default notifierValidator;
