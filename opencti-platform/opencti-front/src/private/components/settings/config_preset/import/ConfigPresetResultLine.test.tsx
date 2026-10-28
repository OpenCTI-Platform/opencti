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

  it('shows a reason that is not known as the backend returns it', () => {
    testRender(<ConfigPresetResultLine label="Theme" status="FAILED" reason="name: Too small" />);
    expect(screen.getByText('name: Too small')).toBeInTheDocument();
  });

  it.each([
    ['Already exists', 'Already exists'],
    ['Nothing to import', 'Nothing to import'],
    ['Built-in theme', 'Built-in theme'],
    ['Added as "Dark (1)"', 'Added as "Dark (1)"'],
    ['Default theme Dark could not be imported', 'Default theme Dark could not be imported'],
    ['Entity types that cannot be hidden: Foo, Bar', 'Entity types that cannot be hidden: Foo, Bar'],
  ])('translates the reason %s', (reason, text) => {
    testRender(<ConfigPresetResultLine label="Theme" status="SKIPPED" reason={reason} />);
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it('shows an unknown status as is, and no reason when there is none', () => {
    testRender(<ConfigPresetResultLine label="Item" status="SOMETHING" reason={null} />);
    expect(screen.getByText('SOMETHING')).toBeInTheDocument();
  });
});
