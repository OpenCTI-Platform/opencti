export type ConfigurationType = { key: string; value: string; type: string };

export const formatStringToArray = (value: string, stringify?: boolean) => {
  if (!value) return null;
  try {
    const result = JSON.parse(String(value).replace(/'/g, '"'));
    return stringify ? JSON.stringify(result) : result;
  } catch {
    return stringify ? JSON.stringify([value]) : [value];
  }
};

export const formatArrayValues = (conf: ConfigurationType[]) => {
  return conf.map((item) => item.type === 'array' ? ({ ...item, value: formatStringToArray(item.value, true) }) : item);
};

export const formatAdvancedConfigurationForCreation = (advancedConfigs: ConfigurationType[]) => {
  return advancedConfigs.reduce((acc: ConfigurationType[], conf: ConfigurationType) => {
    if (conf.key && conf.value && conf.type) {
      return [...acc, {
        key: conf.key,
        value: conf.type === 'array' ? formatStringToArray(conf.value, true) : conf.value,
        type: conf.type,
      }];
    }
    return acc;
  }, []);
};
