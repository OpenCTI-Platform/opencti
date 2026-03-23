import useGranted, {
  SETTINGS_FILEINDEXING,
  SETTINGS_SECURITYACTIVITY,
  SETTINGS_SETACCESSES,
  SETTINGS_SETAUTH,
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETDISSEMINATION,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMANAGEXTMHUB,
  SETTINGS_SETMARKINGS,
  SETTINGS_SETPARAMETERS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
  SETTINGS_SUPPORT,
  VIRTUAL_ORGANIZATION_ADMIN,
} from '../../../utils/hooks/useGranted';

const useSettingsFallbackUrl = (): string => {
  const isGrantedToParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const isGrantedToSecurityAccess = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  const isGrantedToMarkingOnly = useGranted([SETTINGS_SETMARKINGS]);
  const isGrantedToDisseminationListOnly = useGranted([SETTINGS_SETDISSEMINATION]);
  const isGrantedToSsoOnly = useGranted([SETTINGS_SETAUTH]);
  const isGrantedToCustomization = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);
  const isGrantedToTaxonomies = isGrantedToLabels
    || isGrantedToVocabularies
    || isGrantedToKillChainPhases
    || isGrantedToCaseTemplates
    || isGrantedToStatusTemplates;
  const isGrantedToActivity = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isGrantedToFileIndexing = useGranted([SETTINGS_FILEINDEXING]);
  const isGrantedToExperience = useGranted([SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB]);

  if (isGrantedToParameters) return '/dashboard/settings';
  if (isGrantedToSecurityAccess) return '/dashboard/settings/accesses';
  if (isGrantedToMarkingOnly) return '/dashboard/settings/accesses/marking';
  if (isGrantedToDisseminationListOnly) return '/dashboard/settings/accesses/dissemination_list';
  if (isGrantedToSsoOnly) return '/dashboard/settings/accesses/authentications';
  if (isGrantedToCustomization) return '/dashboard/settings/customization';
  if (isGrantedToTaxonomies) return '/dashboard/settings/vocabularies';
  if (isGrantedToActivity) return '/dashboard/settings/activity';
  if (isGrantedToFileIndexing) return '/dashboard/settings/file_indexing';
  if (isGrantedToExperience) return '/dashboard/settings/experience';
  return '/dashboard';
};

export default useSettingsFallbackUrl;
