import useGranted, { BYPASS } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';

// The configuration preset export is reserved to BYPASS users while the CONFIG_PRESET flag is on
const useConfigPresetExportAccess = () => {
  const { isFeatureEnable } = useHelper();
  const isBypass = useGranted([BYPASS]);
  return isBypass && isFeatureEnable('CONFIG_PRESET');
};

export default useConfigPresetExportAccess;
