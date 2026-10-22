import { beforeEach, describe, expect, it, vi } from 'vitest';
import { commitMutation } from '../relay/environment';
import { logXtmHubIgnoredMessage } from './xtmHubLog';

vi.mock('../relay/environment', () => ({ commitMutation: vi.fn(), defaultCommitMutation: {} }));

describe('Function: logXtmHubIgnoredMessage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('sends both origins to the backend log', () => {
    logXtmHubIgnoredMessage('https://other.example', 'https://hub.filigran.io');

    expect(commitMutation).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
      variables: {
        message: 'XTM Hub: message ignored, it comes from "https://other.example" but the configured XTM Hub origin is "https://hub.filigran.io"',
      },
      onError: expect.any(Function),
    }));
  });
});
