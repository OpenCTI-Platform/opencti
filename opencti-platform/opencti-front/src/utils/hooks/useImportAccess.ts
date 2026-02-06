import useGranted, { getCapabilitiesName, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from './useGranted';
import useAuth from './useAuth';
import useHelper from './useHelper';

const useImportAccess = () => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isCapabilitiesInDraftEnabled = isFeatureEnable('CAPABILITIES_IN_DRAFT');

  // Has global import (KNOWLEDGE_KNASKIMPORT in base capabilities)
  const hasImportBaseCapability = useGranted([KNOWLEDGE_KNASKIMPORT]);

  // Has import capability in either Global OR Draft
  const hasAnyImportCapability = useGranted([KNOWLEDGE_KNASKIMPORT], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNASKIMPORT],
  });

  // Forced to create Draft on import if they have no import capability in base but have it in draft
  const isForcedImportToDraft = !hasImportBaseCapability && hasAnyImportCapability;

  // Only access to Import Draft Tab
  const userCapabilities = getCapabilitiesName(me.capabilities);
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);

  const hasAnyKnowledgeCapability = [...userCapabilities, ...userCapabilitiesInDraft]
    .some((cap) => cap.includes(KNOWLEDGE));

  const hasOnlyAccessToImportDraftTab = isCapabilitiesInDraftEnabled
    && !hasImportBaseCapability
    && hasAnyKnowledgeCapability;

  return {
    isForcedImportToDraft,
    hasOnlyAccessToImportDraftTab,
  };
};

export default useImportAccess;
