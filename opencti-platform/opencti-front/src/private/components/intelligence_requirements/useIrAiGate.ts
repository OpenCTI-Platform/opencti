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

import { useChatbot } from '@components/chatbox/ChatbotContext';
import { useFormatter } from '../../../components/i18n';
import useAI from '../../../utils/hooks/useAI';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';

// The rules of the platform AI buttons (same as AI Insights): hidden when AI is disabled,
// disabled with a reason without EE / token, terms of use to accept when XTM One is configured.
const useIrAiGate = (featureLabel: string) => {
  const { t_i18n } = useFormatter();
  const { enabled, fullyActive } = useAI();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  let xtmOneConfigured: boolean;
  try {
    xtmOneConfigured = useChatbot().xtmOneConfigured === true;
  } catch {
    // outside of the chatbot provider
    xtmOneConfigured = false;
  }
  const termsPending = xtmOneConfigured && !fullyActive;
  let disabledReason: string | null = null;
  if (!isEnterpriseEdition) disabledReason = `${t_i18n(featureLabel)}: ${t_i18n('requires the Enterprise Edition.')}`;
  else if (termsPending && !isAdmin) disabledReason = t_i18n('Ask Ariane isn\'t activated yet. Please reach out to your administrator to enable this feature.');
  else if (!xtmOneConfigured && !fullyActive) disabledReason = t_i18n('To use this AI feature in the enterprise edition, please add a token.');
  return { visible: enabled, xtmOneConfigured, termsPending, disabledReason };
};

export default useIrAiGate;
