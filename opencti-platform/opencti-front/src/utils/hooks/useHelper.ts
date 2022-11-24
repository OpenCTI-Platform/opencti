import useAuth from './useAuth';
import platformModuleHelper from '../platformModulesHelper';

const useHelper = () => {
  const { settings } = useAuth();
  return platformModuleHelper(settings);
};

export default useHelper;
