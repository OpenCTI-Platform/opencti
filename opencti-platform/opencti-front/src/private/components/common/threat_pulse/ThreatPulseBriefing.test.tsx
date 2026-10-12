import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { APP_BASE_PATH } from '../../../../relay/environment';
import ThreatPulseBriefing from './ThreatPulseBriefing';

const { fetchAgentsForIntent, callAgentStream } = vi.hoisted(() => ({
  fetchAgentsForIntent: vi.fn(),
  callAgentStream: vi.fn(),
}));

vi.mock('../../../../utils/ai/agentApi', () => ({ fetchAgentsForIntent, callAgentStream }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => true }));
vi.mock('../../chatbox/ChatbotContext', () => ({ useChatbot: () => ({ xtmOneConfigured: true }) }));

const agent = { id: 'a1', name: 'Sector Pulse Briefing', slug: 'sector-pulse-briefing' };

const sentPlatformUrl = async (settings: Record<string, unknown>) => {
  testRender(
    <ThreatPulseBriefing period="last_7_days" sectorBucket="finance" regionBucket={null} />,
    { userContext: createMockUserContext({ settings }) },
  );
  fireEvent.click(await screen.findByTestId('threat-pulse-briefing-button'));
  await waitFor(() => expect(callAgentStream).toHaveBeenCalled());
  return JSON.parse(callAgentStream.mock.calls[0][1]).platform_url;
};

describe('ThreatPulseBriefing', () => {
  beforeEach(() => {
    fetchAgentsForIntent.mockReset().mockResolvedValue([agent]);
    callAgentStream.mockReset().mockResolvedValue({ content: 'Brief', status: 'success' });
  });

  it('should send the agent the canonical platform URL, base path included', async () => {
    expect(await sentPlatformUrl({ platform_url: 'https://opencti.example/octi' })).toBe('https://opencti.example/octi');
  });

  it('should fall back to the address the platform is served from, base path included', async () => {
    expect(await sentPlatformUrl({ platform_url: null })).toBe(`${window.location.origin}${APP_BASE_PATH}`);
  });
});
