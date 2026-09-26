import { screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import StixCoreObjectAskAI from './StixCoreObjectAskAI';

const { mockUseChatbot, responseDialogProps } = vi.hoisted(() => ({
  mockUseChatbot: vi.fn(),
  responseDialogProps: vi.fn(),
}));

vi.mock('@components/chatbox/ChatbotContext', () => ({ useChatbot: mockUseChatbot }));
vi.mock('../../../../utils/ai/ResponseDialog', () => ({
  default: (props: unknown) => {
    responseDialogProps(props);
    return null;
  },
}));
vi.mock('../form/FilesNativeField', () => ({ default: () => null }));

type DialogProps = { agentMode: { intent: string; action: string; inputContent: string; format: string } | null };

const lastDialogProps = (): DialogProps => {
  const { calls } = responseDialogProps.mock;
  return calls[calls.length - 1][0] as DialogProps;
};

const generate = async (xtmOneConfigured: boolean) => {
  mockUseChatbot.mockReturnValue({ xtmOneConfigured });
  const rendered = testRender(
    <StixCoreObjectAskAI
      instanceId="report--0001"
      instanceName="APT42 spear-phishing wave"
      instanceType="Report"
      type="container"
      optionsOpen={true}
      handleCloseOptions={vi.fn()}
    />,
  );
  await rendered.user.click(screen.getByRole('button', { name: 'Generate' }));
  return rendered;
};

describe('StixCoreObjectAskAI container report', () => {
  beforeEach(() => {
    mockUseChatbot.mockReset();
    responseDialogProps.mockReset();
  });

  it('routes the report through the XTM One agent bound to cti.container_report when XTM One is configured', async () => {
    const { relayEnv } = await generate(true);

    const { agentMode } = lastDialogProps();
    expect(agentMode?.intent).toBe('cti.container_report');
    expect(agentMode?.action).toBe('report');
    expect(agentMode?.inputContent).toContain('OpenCTI container with ID: report--0001');
    expect(agentMode?.format).toBe('html');
    // The legacy mutation, which fails without the legacy AI configuration, is never sent.
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('keeps the legacy mutation when XTM One is not configured', async () => {
    const { relayEnv } = await generate(false);

    expect(lastDialogProps().agentMode).toBeNull();
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.node.params.name).toBe('StixCoreObjectAskAIContainerReportMutation');
  });
});
