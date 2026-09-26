import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../tests/test-render';
import ResponseDialog from './ResponseDialog';

const { fetchAgentsForIntent, execute } = vi.hoisted(() => ({
  fetchAgentsForIntent: vi.fn(),
  execute: vi.fn(),
}));

vi.mock('./agentApi', () => ({ fetchAgentsForIntent }));
vi.mock('./useAgentStream', () => ({
  default: () => ({ content: '', loading: false, error: undefined, execute, abort: vi.fn() }),
}));
vi.mock('../hooks/useAI', () => ({ default: () => ({ fullyActive: false }) }));

const agent = { id: 'a1', name: 'OpenCTI Entity Insights', slug: 'opencti-entity-insights' };

const renderDialog = () => testRender(
  <ResponseDialog
    id="bus-1"
    isOpen={true}
    isDisabled={false}
    handleClose={vi.fn()}
    handleAccept={vi.fn()}
    handleFollowUp={vi.fn()}
    content=""
    setContent={vi.fn()}
    format="text"
    followUpActions={[]}
    agentMode={{ intent: 'cti.container_report', action: 'report', inputContent: 'Write a report', format: 'html' }}
  />,
);

describe('ResponseDialog agent mode', () => {
  beforeEach(() => {
    fetchAgentsForIntent.mockReset();
    execute.mockReset();
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
});
