const entityValidators = new Map();
export const registerEntityValidator = (type, validators) => {
    entityValidators.set(type, validators);
};
export const getEntityValidatorCreation = (type) => {
    var _a;
    return (_a = entityValidators.get(type)) === null || _a === void 0 ? void 0 : _a.validatorCreation;
};
export const getEntityValidatorUpdate = (type) => {
    var _a;
    return (_a = entityValidators.get(type)) === null || _a === void 0 ? void 0 : _a.validatorUpdate;
};
