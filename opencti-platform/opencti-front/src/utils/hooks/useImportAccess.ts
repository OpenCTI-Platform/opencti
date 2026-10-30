import useGranted, { KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNUPDATE } from './useGranted';

const useImportAccess = () => {
  // Has global import (KNOWLEDGE_KNASKIMPORT in base capabilities)
  const hasImportBaseCapability = useGranted([KNOWLEDGE_KNASKIMPORT]);

  // Has import capability in either Global OR Draft
  const hasAnyImportCapability = useGranted([KNOWLEDGE_KNASKIMPORT], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNASKIMPORT],
  });

  // Has create/update knowledge only in draft (not in main)
  const hasKnowledgeUpdateInMain = useGranted([KNOWLEDGE_KNUPDATE]);
  const hasKnowledgeUpdateInDraft = useGranted([], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNUPDATE],
  });
  const hasKnowledgeUpdateInDraftOnly = !hasKnowledgeUpdateInMain && hasKnowledgeUpdateInDraft;

  const hasFormIntakeInMain = useGranted([KNOWLEDGE_KNFORMINTAKE]);

  // Forced to create Draft on import if they have no import capability in base but have it in draft,
  // or if they only have KNOWLEDGE_KNUPDATE in draft (not in main).
  const isForcedImportToDraft = (!hasImportBaseCapability && hasAnyImportCapability) || hasKnowledgeUpdateInDraftOnly;

  // Only access to Import Draft Tab: requires at minimum KNOWLEDGE_KNUPDATE (in main or draft)
  const hasKnowledgeUpdate = useGranted([KNOWLEDGE_KNUPDATE], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNUPDATE],
  });

  const hasOnlyAccessToImportDraftTab = !hasImportBaseCapability && hasKnowledgeUpdate;

  // Can submit forms (in main or in draft) but cannot import files: the import dialog only offers the forms
  const hasFormIntakeCapability = useGranted([KNOWLEDGE_KNFORMINTAKE], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNFORMINTAKE],
  });
  const hasOnlyAccessToFormImport = hasFormIntakeCapability && !hasAnyImportCapability;

  // Same rule as formSubmit (canSubmitFormTo): Create / Update knowledge or the form capability, in main or in draft,
  // or Import knowledge granted in draft (a form is then submitted into a draft). Import knowledge in main is not enough.
  const canSubmitForms = useGranted([KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNFORMINTAKE], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNASKIMPORT],
  });
  const canSubmitFormsInMain = useGranted([KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNFORMINTAKE]);

  // A form is submitted to a draft when it cannot be submitted to main (canSubmitFormTo), and, as for a file import, when
  // the user can only import in draft, unless the form capability is held in main. File imports are not concerned.
  const isForcedFormSubmissionToDraft = (isForcedImportToDraft && !hasFormIntakeInMain) || (canSubmitForms && !canSubmitFormsInMain);

  return {
    isForcedImportToDraft,
    isForcedFormSubmissionToDraft,
    hasOnlyAccessToImportDraftTab,
    hasOnlyAccessToFormImport,
    canSubmitForms,
  };
};

export default useImportAccess;
