import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntLatestRuns from './HuntLatestRuns';

const renderWithoutRuns = async (canEdit: boolean) => {
  const { relayEnv } = testRender(<HuntLatestRuns huntId="hunt-1" canEdit={canEdit} />);
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation({ data: { huntRuns: { edges: [] } } } as never);
  });
  return screen.getByTestId('hunt-latest-runs-empty');
};

describe('Latest runs of a hunt', () => {
  it('names the next step to a user who can edit the hunt', async () => {
    expect(await renderWithoutRuns(true)).toHaveTextContent('Next step: Run now at the top of the page');
  });

  it('tells a user who can only view the hunt who can run it, without naming a control', async () => {
    const empty = await renderWithoutRuns(false);
    expect(empty).toHaveTextContent('Each run appears here with its verdict once a user who can edit the hunt runs it or activates it.');
    expect(empty).not.toHaveTextContent('Run now');
  });
});
