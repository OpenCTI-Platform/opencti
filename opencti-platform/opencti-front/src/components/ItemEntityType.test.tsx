import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import ItemEntityType from './ItemEntityType';

describe('ItemEntityType', () => {
  it.each([
    ['has-observable', 'has observable'],
    ['component-of', 'component of'],
    ['procedure-command', 'Command'],
    ['procedure-source', 'Sources'],
  ])('translates the %s relationship label', (relationshipType, label) => {
    testRender(<ItemEntityType entityType={relationshipType} />);
    expect(screen.getByText(label)).toBeInTheDocument();
  });
});
