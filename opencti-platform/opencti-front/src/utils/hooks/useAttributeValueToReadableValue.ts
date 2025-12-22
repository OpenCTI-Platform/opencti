import useAttributes from './useAttributes';
import { useFormatter } from '../../components/i18n';

const useAttributeValueToReadableValue = (value: string | boolean | string[] | number, key: string) => {
  const { dateAttributes } = useAttributes();
  const { fldt } = useFormatter();

  const result = dateAttributes.includes(key) ? fldt(value) : value;

  if (result === true) return 'TRUE';
  if (result === false) return 'FALSE';
  if (Array.isArray(result)) return result.join('\n');
  if (typeof result === 'number') return result.toString();

  return result;
};

export default useAttributeValueToReadableValue;
