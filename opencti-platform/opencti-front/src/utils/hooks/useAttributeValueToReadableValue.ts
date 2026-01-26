import useAttributes from './useAttributes';
import { useFormatter } from '../../components/i18n';

const useAttributeValueToReadableValue = () => {
  const { dateAttributes } = useAttributes();
  const { fldt } = useFormatter();

  const attributeToReadableValue = (value: string | boolean | string[] | number, key: string) => {
    const result = dateAttributes.includes(key) ? fldt(value) : value;

    if (result === true) return 'TRUE';
    if (result === false) return 'FALSE';
    if (Array.isArray(result)) return result.join('\n');
    if (typeof result === 'number') return result.toString();

    return result;
  };

  return attributeToReadableValue;
};

export default useAttributeValueToReadableValue;
