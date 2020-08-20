import * as R from 'ramda';

export const dictAttributes = { hashes: { key: 'algorithm', value: 'hash' } };
export const dictReconstruction = (dataKey, attributeValue) => {
  if (dictAttributes[dataKey]) {
    const { key, value } = dictAttributes[dataKey];
    const jsonContent = JSON.parse(attributeValue);
    return R.pipe(
      R.toPairs,
      R.map(([lab, val]) => ({ [key]: lab, [value]: val }))
    )(jsonContent);
  }
  return attributeValue;
};
