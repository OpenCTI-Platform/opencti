import RE2 from 're2';

// Built inside the render worker; patternFromValue reaches the Python bridge on the main thread through a host call
export const extractWithRegexp = (regexp: string, groupIndex: number, value: string) => {
  const myRegexp = new RE2(regexp, 'g');
  const matches = myRegexp.exec(value);
  if (matches != null && matches[groupIndex] != null) {
    return matches[groupIndex];
  }
  return value;
};

export const decisionMatrix = (value: unknown, defaultValue: unknown, matrix: { value: unknown; result: unknown }[]) => {
  for (let i = 0; i < matrix.length; i += 1) {
    const v = matrix[i];
    if (v.value === value) {
      return v.result;
    }
  }
  return defaultValue;
};

export const withJsonMapperHelpers = <T extends object>(data: T, hostCall?: (name: string, args: unknown[]) => string) => ({
  ...data,
  patternFromValue: (k: unknown, value: unknown) => {
    if (!hostCall) {
      throw new Error('Host calls are not available in this worker');
    }
    return hostCall('patternFromValue', [k, value]);
  },
  extractWithRegexp,
  decisionMatrix,
});
