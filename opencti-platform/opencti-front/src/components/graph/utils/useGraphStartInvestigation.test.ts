import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useGraphStartInvestigation from './useGraphStartInvestigation';

type CommitConfig = {
  variables: unknown;
  onCompleted: (response: { workspaceAdd: { id: string } | null }, errors?: readonly { message: string }[] | null) => void;
};

const mocks = vi.hoisted(() => ({
  commit: vi.fn<(config: CommitConfig) => void>(),
  navigate: vi.fn(),
  notifyError: vi.fn(),
  granted: true,
  draft: null as unknown,
}));

vi.mock('react-router', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('../../../utils/hooks/useApiMutation', () => ({ default: () => [mocks.commit] }));
vi.mock('../../../utils/hooks/useGranted', () => ({ default: () => mocks.granted, INVESTIGATION_INUPDATE: 'INVESTIGATION_INUPDATE' }));
vi.mock('../../../utils/hooks/useDraftContext', () => ({ default: () => mocks.draft }));
vi.mock('../../../relay/environment', () => ({ MESSAGING$: { notifyError: mocks.notifyError } }));
vi.mock('../../i18n', () => ({ useFormatter: () => ({ t_i18n: (key: string) => (key === 'entity_Investigation' ? 'Investigation' : key) }) }));

describe('useGraphStartInvestigation', () => {
  beforeEach(() => {
    mocks.commit.mockReset();
    mocks.navigate.mockReset();
    mocks.notifyError.mockReset();
    mocks.granted = true;
    mocks.draft = null;
  });

  const start = (name = 'Investigation of Emotet') => {
    const { result } = renderHook(() => useGraphStartInvestigation());
    result.current?.(name, ['malware--1']);
    return mocks.commit.mock.calls[0][0];
  };

  it('names the investigation after an entity of one character with its type, the platform taking two at least', () => {
    expect(start('X').variables).toEqual({
      input: { type: 'investigation', name: 'Investigation X', investigated_entities_ids: ['malware--1'] },
    });
  });

  it('creates the investigation with the entities and opens it', () => {
    const config = start();
    expect(config.variables).toEqual({
      input: { type: 'investigation', name: 'Investigation of Emotet', investigated_entities_ids: ['malware--1'] },
    });
    config.onCompleted({ workspaceAdd: { id: 'workspace-1' } }, null);
    expect(mocks.navigate).toHaveBeenCalledWith('/dashboard/workspaces/investigations/workspace-1');
    expect(mocks.notifyError).not.toHaveBeenCalled();
  });

  it('tells the user why the investigation was not created and stays on the graph', () => {
    const config = start();
    config.onCompleted({ workspaceAdd: null }, [{ message: 'You are not allowed to do this.' }]);
    expect(mocks.notifyError).toHaveBeenCalledWith('You are not allowed to do this.');
    expect(mocks.navigate).not.toHaveBeenCalled();
  });

  it('offers nothing to users who may not investigate or work in a draft', () => {
    mocks.granted = false;
    expect(renderHook(() => useGraphStartInvestigation()).result.current).toBeNull();
    mocks.granted = true;
    mocks.draft = { id: 'draft-1' };
    expect(renderHook(() => useGraphStartInvestigation()).result.current).toBeNull();
  });
});
