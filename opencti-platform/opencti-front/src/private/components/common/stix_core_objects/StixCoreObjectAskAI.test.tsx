import { act, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { MESSAGING$ } from '../../../../relay/environment';
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

type DialogProps = {
  id: string;
  isOpen: boolean;
  handleClose: () => void;
  handleAccept: (content: string) => void;
  agentMode: { intent: string; action: string; inputContent: string; format: string } | null;
};

const lastDialogProps = (): DialogProps => {
  const { calls } = responseDialogProps.mock;
  return calls[calls.length - 1][0] as DialogProps;
};

const generate = async (xtmOneConfigured: boolean, { cguStatus = 'enabled', isAdmin = false } = {}) => {
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
    {
      userContext: createMockUserContext({
        settings: { filigran_chatbot_ai_cgu_status: cguStatus },
        me: isAdmin ? { capabilities: [{ name: 'BYPASS' }] } : undefined,
      }),
    },
  );
  await rendered.user.click(screen.getByRole('button', { name: 'Generate' }));
  return rendered;
};

const cancelDestination = async (user: ReturnType<typeof testRender>['user']) => {
  const destination = screen.getByRole('dialog', { name: 'Select destination' });
  await user.click(within(destination).getByRole('button', { name: 'Cancel' }));
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

  it('unmounts the agent dialog on close so a new generation never re-runs the previous agent selection', async () => {
    await generate(true);
    const callsBeforeClose = responseDialogProps.mock.calls.length;

    act(() => lastDialogProps().handleClose());

    // Closing re-renders the component; a still-mounted dialog would render again.
    expect(responseDialogProps.mock.calls.length).toBe(callsBeforeClose);
  });

  it('does not bring the unmounted agent dialog back when the destination is cancelled', async () => {
    const { user } = await generate(true);
    act(() => lastDialogProps().handleAccept('<p>APT42 report</p>'));
    const callsBeforeCancel = responseDialogProps.mock.calls.length;

    await cancelDestination(user);

    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Select destination' })).not.toBeInTheDocument());
    expect(responseDialogProps.mock.calls.length).toBe(callsBeforeCancel);
  });

  it('asks an administrator to accept the Filigran AI terms first, as the other XTM One entry points do', async () => {
    // The chatbot routes refuse every call until then: the dialog could only say no agent is available.
    const { relayEnv } = await generate(true, { cguStatus: 'pending', isAdmin: true });

    expect(await screen.findByText('Validate the Filigran AI Terms')).toBeInTheDocument();
    expect(responseDialogProps).not.toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('tells anyone else that the assistant is not activated yet while the terms are pending', async () => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError');
    const { relayEnv } = await generate(true, { cguStatus: 'pending' });

    expect(notifyError).toHaveBeenCalledWith('Ask Ariane isn\'t activated yet. Please reach out to your administrator to enable this feature.');
    expect(screen.queryByText('Validate the Filigran AI Terms')).not.toBeInTheDocument();
    expect(responseDialogProps).not.toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    notifyError.mockRestore();
  });

  it('keeps the legacy mutation when XTM One is not configured', async () => {
    const { relayEnv } = await generate(false);

    expect(lastDialogProps().agentMode).toBeNull();
    const operations = relayEnv.mock.getAllOperations();
    expect(operations).toHaveLength(1);
    expect(operations[0].request.node.params.name).toBe('StixCoreObjectAskAIContainerReportMutation');
  });

  it('reopens the legacy dialog when the destination is cancelled', async () => {
    const { user } = await generate(false);
    act(() => lastDialogProps().handleAccept('APT42 report'));
    expect(lastDialogProps().isOpen).toBe(false);

    await cancelDestination(user);

    expect(lastDialogProps().isOpen).toBe(true);
  });
});
