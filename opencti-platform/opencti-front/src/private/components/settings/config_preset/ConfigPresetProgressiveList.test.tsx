import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetProgressiveList from './ConfigPresetProgressiveList';

const rows = (count: number) => Array.from({ length: count }, (_, index) => ({ key: `row-${index}` }));

describe('ConfigPresetProgressiveList', () => {
  it('shows a short list as it is, without a button', () => {
    testRender(<ConfigPresetProgressiveList items={rows(3)} getKey={(row) => row.key} renderItem={(row) => <div>{row.key}</div>} />);
    expect(screen.getAllByText(/^row-/)).toHaveLength(3);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('mounts one page of a long list and the next one on demand, with the number of rows left', async () => {
    const { user } = testRender(<ConfigPresetProgressiveList items={rows(450)} pageSize={200} getKey={(row) => row.key} renderItem={(row) => <div>{row.key}</div>} />);
    expect(screen.getAllByText(/^row-/)).toHaveLength(200);
    await user.click(screen.getByRole('button', { name: 'Show more (250)' }));
    expect(screen.getAllByText(/^row-/)).toHaveLength(400);
    await user.click(screen.getByRole('button', { name: 'Show more (50)' }));
    expect(screen.getAllByText(/^row-/)).toHaveLength(450);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
