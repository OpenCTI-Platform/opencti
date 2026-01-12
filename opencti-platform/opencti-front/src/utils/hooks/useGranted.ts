import useAuth from './useAuth';
import useHelper from './useHelper';

export const OPENCTI_ADMIN_UUID = '88ec0c6a-13ce-5e39-b486-354fe4a7084f';
export const BYPASS = 'BYPASS';
export const KNOWLEDGE = 'KNOWLEDGE';
export const KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE = 'KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE';
export const KNOWLEDGE_KNUPDATE = 'KNOWLEDGE_KNUPDATE';
export const KNOWLEDGE_KNPARTICIPATE = 'KNOWLEDGE_KNPARTICIPATE';
export const KNOWLEDGE_KNFRONTENDEXPORT = 'KNOWLEDGE_KNFRONTENDEXPORT';
export const KNOWLEDGE_KNUPDATE_KNDELETE = 'KNOWLEDGE_KNUPDATE_KNDELETE';
export const KNOWLEDGE_KNUPDATE_KNMERGE = 'KNOWLEDGE_KNUPDATE_KNMERGE';
export const KNOWLEDGE_KNUPDATE_KNORGARESTRICT = 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT';
export const KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS = 'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS';
export const KNOWLEDGE_KNUPLOAD = 'KNOWLEDGE_KNUPLOAD';
export const KNOWLEDGE_KNASKIMPORT = 'KNOWLEDGE_KNASKIMPORT';
export const KNOWLEDGE_KNGETEXPORT = 'KNOWLEDGE_KNGETEXPORT';
export const KNOWLEDGE_KNGETEXPORT_KNASKEXPORT = 'KNOWLEDGE_KNGETEXPORT_KNASKEXPORT';
export const KNOWLEDGE_KNENRICHMENT = 'KNOWLEDGE_KNENRICHMENT';
export const KNOWLEDGE_KNDISSEMINATION = 'KNOWLEDGE_KNDISSEMINATION';
export const EXPLORE = 'EXPLORE';
export const EXPLORE_EXUPDATE = 'EXPLORE_EXUPDATE';
export const EXPLORE_EXUPDATE_EXDELETE = 'EXPLORE_EXUPDATE_EXDELETE';
export const EXPLORE_EXUPDATE_PUBLISH = 'EXPLORE_EXUPDATE_PUBLISH';
export const INVESTIGATION = 'INVESTIGATION';
export const INVESTIGATION_INUPDATE = 'INVESTIGATION_INUPDATE';
export const INVESTIGATION_INUPDATE_INDELETE = 'INVESTIGATION_INUPDATE_INDELETE';
export const MODULES = 'MODULES';
export const MODULES_MODMANAGE = 'MODULES_MODMANAGE';
export const PIRAPI = 'PIRAPI';
export const PIRAPI_PIRUPDATE = 'PIRAPI_PIRUPDATE';
export const AUTOMATION = 'AUTOMATION';
export const AUTOMATION_AUTMANAGE = 'AUTOMATION_AUTMANAGE';
export const SETTINGS = 'SETTINGS';
export const VIRTUAL_ORGANIZATION_ADMIN = 'VIRTUAL_ORGANIZATION_ADMIN';
export const TAXIIAPI = 'TAXIIAPI';
export const TAXIIAPI_SETCOLLECTIONS = 'TAXIIAPI_SETCOLLECTIONS';
export const INGESTION = 'INGESTION';
export const INGESTION_SETINGESTIONS = 'INGESTION_SETINGESTIONS';
export const CSVMAPPERS = 'CSVMAPPERS';
export const SETTINGS_SETMANAGEXTMHUB = 'SETTINGS_SETMANAGEXTMHUB';
export const SETTINGS_SETPARAMETERS = 'SETTINGS_SETPARAMETERS';
export const SETTINGS_SETACCESSES = 'SETTINGS_SETACCESSES';
export const SETTINGS_SETMARKINGS = 'SETTINGS_SETMARKINGS';
export const SETTINGS_SETDISSEMINATION = 'SETTINGS_SETDISSEMINATION';
export const SETTINGS_SETCUSTOMIZATION = 'SETTINGS_SETCUSTOMIZATION';
export const SETTINGS_SETLABELS = 'SETTINGS_SETLABELS';
export const SETTINGS_SETVOCABULARIES = 'SETTINGS_SETVOCABULARIES';
export const SETTINGS_SETCASETEMPLATES = 'SETTINGS_SETCASETEMPLATES';
export const SETTINGS_SETSTATUSTEMPLATES = 'SETTINGS_SETSTATUSTEMPLATES';
export const SETTINGS_SETKILLCHAINPHASES = 'SETTINGS_SETKILLCHAINPHASES';
export const SETTINGS_SECURITYACTIVITY = 'SETTINGS_SECURITYACTIVITY';
export const SETTINGS_FILEINDEXING = 'SETTINGS_FILEINDEXING';
export const SETTINGS_SUPPORT = 'SETTINGS_SUPPORT';

export const hasCapabilitiesInDraft = (capabilities: string[]) => {
  const { me } = useAuth();
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);
  return capabilities.some((capability) => (
    userCapabilitiesInDraft.includes(capability)
  ));
};

export const isOnlyOrganizationAdmin = () => {
  const { me: user } = useAuth();
  const userCapabilities = user.capabilities.map((n) => n.name);
  return userCapabilities.includes(VIRTUAL_ORGANIZATION_ADMIN) && !userCapabilities.includes(BYPASS) && !userCapabilities.includes(SETTINGS_SETACCESSES);
};

export const getCapabilitiesName = (capabilities: readonly { name: string }[]) => {
  return (capabilities ?? []).map((capability) => capability?.name);
};

export const isBypassUser = (me: { id: string; capabilities: readonly { name: string }[] }) => {
  const userCapabilities = getCapabilitiesName(me.capabilities);
  return userCapabilities.includes(BYPASS);
};

const useGranted = (capabilities: string[], matchAll = false): boolean => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isCapabilitiesInDraftEnabled = isFeatureEnable('CAPABILITIES_IN_DRAFT');

  // Prevent use of the old SETTINGS capability for future uses
  if (capabilities.includes(SETTINGS)) {
    throw new Error('The SETTINGS capability should not be used');
  }

  let userCapabilities: string[] = [];
  const userBaseCapabilities = getCapabilitiesName(me.capabilities);

  if (isBypassUser(me)) {
    return true;
  }

  // If the user is in draft mode, add capabilities in draft to the base capabilities
  if (isCapabilitiesInDraftEnabled && me.draftContext) {
    const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);
    userCapabilities = Array.from(new Set([...userBaseCapabilities, ...userCapabilitiesInDraft]));
  } else {
    userCapabilities = userBaseCapabilities;
  }

  // Check if any of the user capabilities includes the requested capability as a substring
  const capabilityMatches = (requestedCapability: string) =>
    userCapabilities.some((u) => requestedCapability !== BYPASS && u.includes(requestedCapability));

  return matchAll
    ? capabilities.every(capabilityMatches)
    : capabilities.some(capabilityMatches);
};

export default useGranted;
