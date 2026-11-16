import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import ItemEntityType from './ItemEntityType';

describe('ItemEntityType', () => {
  it.each([
    ['procedure-observable', 'Observables'],
    ['procedure-command', 'Command'],
    ['procedure-source', 'Sources'],
  ])('translates the %s nested reference label', (relationshipType, label) => {
    testRender(<ItemEntityType entityType={relationshipType} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
