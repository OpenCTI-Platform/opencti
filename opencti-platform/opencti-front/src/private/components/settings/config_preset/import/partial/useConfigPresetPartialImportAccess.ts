import useGranted, { BYPASS } from '../../../../../../utils/hooks/useGranted';
import useHelper from '../../../../../../utils/hooks/useHelper';

// The partial import from a configuration bundle is reserved to BYPASS users while the CONFIG_PRESET flag is on, like the wizard:
// for the others, the screen keeps its own import only
const useConfigPresetPartialImportAccess = () => {
  const { isFeatureEnable } = useHelper();
  const isBypass = useGranted([BYPASS]);
  return isBypass && isFeatureEnable('CONFIG_PRESET');
};

export default useConfigPresetPartialImportAccess;
