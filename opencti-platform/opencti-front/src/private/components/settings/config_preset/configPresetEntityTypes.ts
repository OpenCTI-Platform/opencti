// The entity types of a list the backend joined with ', ', by their translated names (the name itself when it has none)
export const translateConfigPresetEntityTypes = (t_i18n: (key: string) => string, types: string): string => {
  return types.split(', ').map((type) => {
    const translated = t_i18n(`entity_${type}`);
    return translated === `entity_${type}` ? type : translated;
  }).join(', ');
};
