export const cropNumber = (value: number, options: { min?: number, max?: number }) => {
  let newValue = value;
  if (options.min !== undefined) {
    if (options.max !== undefined && options.min > options.max) {
      throw Error('Incorrect inputs to cropNumber, min cannot be greater than max');
    }
    newValue = Math.max(newValue, options.min);
  }
  if (options.max !== undefined) {
    newValue = Math.min(newValue, options.max);
  }

  return newValue;
};
