import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import ConfigPresetResultLine from './ConfigPresetResultLine';

describe('ConfigPresetResultLine', () => {
  it.each([['CREATED', 'Created'], ['OVERWRITTEN', 'Overwritten'], ['SKIPPED', 'Skipped'], ['FAILED', 'Failed']])('renders the status %s', (status, text) => {
    testRender(<ConfigPresetResultLine label="Banner" status={status} />);
    expect(screen.getByText('Banner')).toBeInTheDocument();
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it('shows the reason as the backend returns it', () => {
    testRender(<ConfigPresetResultLine label="Theme" status="FAILED" reason="Theme name already exists" />);
    expect(screen.getByText('Theme name already exists')).toBeInTheDocument();
  });

  it('shows an unknown status as is, and no reason when there is none', () => {
    testRender(<ConfigPresetResultLine label="Item" status="SOMETHING" reason={null} />);
    expect(screen.getByText('SOMETHING')).toBeInTheDocument();
  });
});
