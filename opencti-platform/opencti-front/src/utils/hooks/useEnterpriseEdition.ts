import useAuth from './useAuth';
import { isNotEmptyField } from '../utils';

const useEnterpriseEdition = (): boolean => {
  const { settings } = useAuth();
  return isNotEmptyField(settings.enterprise_edition);
};

export default useEnterpriseEdition;
