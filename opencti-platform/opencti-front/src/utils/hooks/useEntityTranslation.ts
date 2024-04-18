import { useFormatter } from '../../components/i18n';

const useEntityTranslation = () => {
  const { t_i18n } = useFormatter();

  const translateEntityType = (type: string) => {
    if (t_i18n(`entity_${type}`) !== `entity_${type}`) {
      return t_i18n(`entity_${type}`);
    }
    if (t_i18n(`relationship_${type}`) !== `relationship_${type}`) {
      return t_i18n(`relationship_${type}`);
    }
    return t_i18n(type);
  };

  return {
    translateEntityType,
  };
};

export default useEntityTranslation;
