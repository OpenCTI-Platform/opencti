// eslint-disable-next-line import/prefer-default-export
export const arrayGroupBy = (input: any[], key: string) => {
  return input.reduce((acc, currentValue) => {
    const groupKey = currentValue[key];
    if (!acc[groupKey]) acc[groupKey] = [];
    acc[groupKey].push(currentValue);
    return acc;
  }, {});
};
