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

import useAuth from './useAuth';
import { useChatbot } from '@components/chatbox/ChatbotContext';

const useAI = (): {
  configured: boolean;
  enabled: boolean;
  fullyActive: boolean;
} => {
  const { settings } = useAuth();
  let xtmOneConfigured;

  try {
    const chatbot = useChatbot();
    xtmOneConfigured = chatbot.xtmOneConfigured === true;
  } catch (_) {
    // Graceful fallback if used outside of ChatbotProvider
    xtmOneConfigured = false;
  }

  if (xtmOneConfigured) {
    const isChatbotEnabled = settings.filigran_chatbot_ai_cgu_status === 'enabled';
    const isChatbotDisabled = settings.filigran_chatbot_ai_cgu_status === 'disabled';
    return {
      enabled: !isChatbotDisabled,
      configured: true,
      fullyActive: isChatbotEnabled,
    };
  }

  return {
    enabled: settings.platform_ai_enabled,
    configured: settings.platform_ai_has_token,
    fullyActive: settings.platform_ai_enabled && settings.platform_ai_has_token,
  };
};

export default useAI;
