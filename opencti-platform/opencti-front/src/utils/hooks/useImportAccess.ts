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

  // Has the form intake capability only in draft (not in main, and no create/update in main either)
  const hasFormIntakeInMain = useGranted([KNOWLEDGE_KNFORMINTAKE]);
  const hasFormIntakeInDraft = useGranted([], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNFORMINTAKE],
  });
  const hasFormIntakeInDraftOnly = !hasFormIntakeInMain && !hasKnowledgeUpdateInMain && hasFormIntakeInDraft;

  // Forced to create Draft on import if they have no import capability in base but have it in draft,
  // or if they only have KNOWLEDGE_KNUPDATE or the form intake capability in draft (not in main).
  const isForcedImportToDraft = (!hasImportBaseCapability && hasAnyImportCapability)
    || hasKnowledgeUpdateInDraftOnly
    || hasFormIntakeInDraftOnly;

  // A form is submitted where the form capability is held: with it in main, the submission can stay in main (objects
  // created on the fly then need Create / Update knowledge in main), whatever the user can do in draft.
  const isForcedFormSubmissionToDraft = isForcedImportToDraft && !hasFormIntakeInMain;

  // Only access to Import Draft Tab: requires at minimum KNOWLEDGE_KNUPDATE (in main or draft)
  const hasKnowledgeUpdate = useGranted([KNOWLEDGE_KNUPDATE], false, {
    capabilitiesInDraft: [KNOWLEDGE_KNUPDATE],
  });

  const hasOnlyAccessToImportDraftTab = !hasImportBaseCapability && hasKnowledgeUpdate;

  // A draft page (and its workflow) needs KNOWLEDGE_KNUPDATE: a form-only user cannot open the draft their submission created
  const canOpenDraft = hasKnowledgeUpdate;

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

  return {
    isForcedImportToDraft,
    isForcedFormSubmissionToDraft,
    hasOnlyAccessToImportDraftTab,
    hasOnlyAccessToFormImport,
    canSubmitForms,
    canOpenDraft,
  };
};

export default useImportAccess;
