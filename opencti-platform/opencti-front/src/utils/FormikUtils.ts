import { adaptFieldValue } from './String';

const formikFieldToEditInput = <T extends Record<string, unknown>>(
  current: T,
  previous: T,
) => {
  const object = { ...current };
  Object.entries(previous).forEach(([key, value]) => {
    if (object[key] === value) {
      delete object[key];
    }
  });
  return Object.entries(object).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
};

export default formikFieldToEditInput;
