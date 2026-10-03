import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../tests/test-render';
import ResponseDialog from './ResponseDialog';

const { fetchAgentsForIntent, execute, stream } = vi.hoisted(() => ({
  fetchAgentsForIntent: vi.fn(),
  execute: vi.fn(),
  stream: { raw: '' },
}));

vi.mock('./agentApi', () => ({ fetchAgentsForIntent }));
vi.mock('./useAgentStream', () => ({
  default: (options?: { transformContent?: (raw: string) => string }) => ({
    content: options?.transformContent ? options.transformContent(stream.raw) : stream.raw,
    loading: false,
    error: undefined,
    execute,
    abort: vi.fn(),
  }),
}));
vi.mock('../hooks/useAI', () => ({ default: () => ({ fullyActive: false }) }));

const agent = { id: 'a1', name: 'OpenCTI Entity Insights', slug: 'opencti-entity-insights' };

const reportAgentMode = { intent: 'cti.container_report', action: 'report' as const, inputContent: 'Write a report', format: 'html' };

const dialog = ({ content = '', setContent = vi.fn() }: { content?: string; setContent?: (value: string) => void } = {}) => (
  <ResponseDialog
    id="bus-1"
    isOpen={true}
    isDisabled={false}
    handleClose={vi.fn()}
    handleAccept={vi.fn()}
    handleFollowUp={vi.fn()}
    content={content}
    setContent={setContent}
    format="text"
    followUpActions={[]}
    agentMode={reportAgentMode}
  />
);

const renderDialog = (props?: Parameters<typeof dialog>[0]) => testRender(dialog(props));

describe('ResponseDialog agent mode', () => {
  beforeEach(() => {
    fetchAgentsForIntent.mockReset();
    execute.mockReset();
    stream.raw = '';
  });

  it('sends a caller-built report prompt as is, from the cache on the first run', async () => {
    fetchAgentsForIntent.mockResolvedValue([agent]);
    renderDialog();

    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));
    expect(fetchAgentsForIntent).toHaveBeenCalledWith('cti.container_report');
    expect(execute).toHaveBeenLastCalledWith('opencti-entity-insights', 'Write a report', false);
  });

  it('bypasses the response cache when the user regenerates', async () => {
    fetchAgentsForIntent.mockResolvedValue([agent]);
    const { user } = renderDialog();
    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));

    await user.click(screen.getByRole('button', { name: 'Regenerate AI response' }));

    await waitFor(() => expect(execute).toHaveBeenCalledTimes(2));
    expect(execute).toHaveBeenLastCalledWith('opencti-entity-insights', 'Write a report', true);
  });

  it('cannot accept a result when no agent serves the intent', async () => {
    fetchAgentsForIntent.mockResolvedValue([]);
    renderDialog();

    await screen.findByText('No agent available for this action. Ask your administrator to configure XTM One.');
    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled();
    expect(execute).not.toHaveBeenCalled();
  });

  it('offers Accept only once the agent has answered, since accepting nothing would clear the caller content', async () => {
    fetchAgentsForIntent.mockResolvedValue([agent]);
    const { rerender } = renderDialog();
    await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));
    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled();

    rerender(dialog({ content: '<p>APT42 report</p>' }));

    expect(screen.getByRole('button', { name: 'Accept' })).toBeEnabled();
  });

  it('drops the code fences and document wrappers a model may put around its HTML report', async () => {
    stream.raw = '```html\n<html><body><h1>APT42 report</h1></body></html>\n```';
    fetchAgentsForIntent.mockResolvedValue([agent]);
    const setContent = vi.fn();
    renderDialog({ setContent });

    await waitFor(() => expect(setContent).toHaveBeenCalledWith('<h1>APT42 report</h1>'));
  });
});
