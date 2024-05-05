import useAuth from './useAuth';
import { isNotEmptyField } from '../utils';

const useXTM = (): { oBasDisableDisplay: boolean, oBasConfigured: boolean } => {
  const { settings } = useAuth();
  return { oBasDisableDisplay: settings.platform_openbas_disable_display ?? false, oBasConfigured: isNotEmptyField(settings.platform_openbas_url) };
};

export default useXTM;
