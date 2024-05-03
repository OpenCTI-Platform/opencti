import useAuth from './useAuth';

const useXTM = (): { disableDisplay: boolean } => {
  const { settings } = useAuth();
  return { disableDisplay: settings.platform_openbas_disable_display ?? false };
};

export default useXTM;
