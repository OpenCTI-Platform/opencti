/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useState } from 'react';
import { useNavigate } from 'react-router';
import { LogoXtmOneIcon } from 'filigran-icon';
import FiligranIcon from '@components/common/FiligranIcon';
import AskAIMenu, { type AskAIAction } from '@components/common/ai/AskAIMenu';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE_KNUPDATE, SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import { useChatbot } from '../chatbox/ChatbotContext';
import InvestigationRunDrawer from './InvestigationRunDrawer';
import RunCaseAutopilotDialog, { AUTOPILOT_TAB_TYPES, type RunCaseAutopilotStarted } from './RunCaseAutopilotDialog';
import { caseAutopilotPath, INVESTIGATION_LAUNCHED$ } from './investigationRunUtils';

interface RunCaseAutopilotAskAIProps {
  subjectId: string;
  subjectType: string;
  /** Path of the entity page, for the entities that have an Autopilot tab. */
  basePath?: string;
}

/** The Ask AI menu of an incident, a case, an indicator or an observable, with "Run Case Autopilot". */
const RunCaseAutopilotAskAI = ({ subjectId, subjectType, basePath }: RunCaseAutopilotAskAIProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  // The enrichment capability depends on the policy picked in the dialog.
  const canInvestigate = useGranted([KNOWLEDGE_KNUPDATE]);
  const draftContext = useDraftContext();
  const { xtmOneConfigured } = useChatbot();
  const { settings: { id: settingsId } } = useAuth();
  const [launching, setLaunching] = useState(false);
  const [eeDialog, setEeDialog] = useState(false);
  const [drawerRunId, setDrawerRunId] = useState<string | null>(null);
  // Investigations act on the live graph and write to their own draft.
  if (draftContext || !canInvestigate) return null;
  const onStarted = ({ runId, caseRef }: RunCaseAutopilotStarted) => {
    setLaunching(false);
    INVESTIGATION_LAUNCHED$.next(subjectId);
    if (basePath && AUTOPILOT_TAB_TYPES.includes(subjectType)) {
      navigate(`${basePath}/autopilot?run=${encodeURIComponent(runId)}`);
    } else if (caseRef) {
      navigate(caseAutopilotPath(caseRef, runId));
    } else {
      // The new case is created in the investigation draft: until the draft is
      // approved, the run is followed from here.
      setDrawerRunId(runId);
    }
  };
  const action: AskAIAction = {
    key: 'run-case-autopilot',
    label: t_i18n('Run Case Autopilot'),
    icon: <FiligranIcon icon={LogoXtmOneIcon} size={16} />,
    onSelect: () => (isEnterpriseEdition ? setLaunching(true) : setEeDialog(true)),
    disabledReason: isEnterpriseEdition && xtmOneConfigured === false ? t_i18n('XTM One is not connected') : null,
    testId: 'run-case-autopilot',
  };
  return (
    <>
      <AskAIMenu actions={[action]} />
      {isEnterpriseEdition ? (
        <>
          <RunCaseAutopilotDialog
            open={launching}
            subjectId={subjectId}
            subjectType={subjectType}
            onClose={() => setLaunching(false)}
            onStarted={onStarted}
          />
          <InvestigationRunDrawer
            runId={drawerRunId}
            currentEntityId={subjectId}
            onClose={() => setDrawerRunId(null)}
            onRunStarted={(runId) => {
              setDrawerRunId(runId);
              INVESTIGATION_LAUNCHED$.next(subjectId);
            }}
          />
        </>
      ) : isAdmin ? (
        <EnterpriseEditionAgreement open={eeDialog} onClose={() => setEeDialog(false)} settingsId={settingsId} />
      ) : (
        <FeedbackCreation
          openDrawer={eeDialog}
          handleCloseDrawer={() => setEeDialog(false)}
          initialValue={{ description: t_i18n('I would like to use the Enterprise Edition feature Case Autopilot but the Enterprise Edition is not activated.') }}
        />
      )}
    </>
  );
};

export default RunCaseAutopilotAskAI;
