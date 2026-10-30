import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import ItemIcon from './ItemIcon';

describe('ItemIcon', () => {
  it.each([
    ['Sync', 'CloudSyncOutlinedIcon'],
    ['IngestionRss', 'RssFeedOutlinedIcon'],
    ['IngestionCsv', 'TableViewOutlinedIcon'],
    ['IngestionJson', 'DataObjectOutlinedIcon'],
    ['IngestionTaxii', 'TravelExploreOutlinedIcon'],
    ['IngestionTaxiiCollection', 'PublishOutlinedIcon'],
  ])('should show the Integrations icon for %s', (type, testId) => {
    testRender(<ItemIcon type={type} />);

    expect(screen.getByTestId(testId)).toBeInTheDocument();
  });

  it('should keep the generic icon for an unknown type', () => {
    testRender(<ItemIcon type="Unknown-Type" />);

    expect(screen.getByTestId('AutoAwesomeMotionIcon')).toBeInTheDocument();
  });
});
