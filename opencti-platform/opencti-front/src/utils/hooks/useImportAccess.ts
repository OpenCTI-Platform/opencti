import useGranted, { getCapabilitiesName, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE } from './useGranted';
import useAuth from './useAuth';

const useImportAccess = () => {
  const { me } = useAuth();

  // Has global import (KNOWLEDGE_KNASKIMPORT in base capabilities)
  const hasImportBaseCapability = useGranted([KNOWLEDGE_KNASKIMPORT]);

  // Has import capability in either Global OR Draft
  const hasAnyImportCapability = useGranted([KNOWLEDGE_KNASKIMPORT], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNASKIMPORT],
  });

  // Has create/update knowledge only in draft (not in main)
  const hasKnowledgeUpdateInMain = useGranted([KNOWLEDGE_KNUPDATE]);
  const hasKnowledgeUpdateInDraftOnly = !hasKnowledgeUpdateInMain && useGranted([], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNUPDATE],
  });

  // Forced to create Draft on import if they have no import capability in base but have it in draft,
  // or if they only have KNOWLEDGE_KNUPDATE in draft (not in main).
  const isForcedImportToDraft = (!hasImportBaseCapability && hasAnyImportCapability) || hasKnowledgeUpdateInDraftOnly;

  // Only access to Import Draft Tab
  const userCapabilities = getCapabilitiesName(me.capabilities);
  const userCapabilitiesInDraft = getCapabilitiesName(me.capabilitiesInDraft);

  const hasAnyKnowledgeCapability = [...userCapabilities, ...userCapabilitiesInDraft]
    .some((cap) => cap.includes(KNOWLEDGE));

  const hasOnlyAccessToImportDraftTab = !hasImportBaseCapability && hasAnyKnowledgeCapability;

  return {
    isForcedImportToDraft,
    hasOnlyAccessToImportDraftTab,
  };
};

export default useImportAccess;
