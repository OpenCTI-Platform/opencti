import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../utils/tests/test-render';
import WidgetRenderContent from './WidgetRenderContent';

describe('WidgetRenderContent', () => {
  it('renders the no data message instead of the widget when a variable is unresolved', () => {
    const { getByText, queryByText } = testRender(
      <WidgetRenderContent isMissingHostEntity={false} isMissingSavedFilters={false} hasUnresolvedVariables queryRef={{}}>
        <div>widget content</div>
      </WidgetRenderContent>,
    );
    expect(getByText('No data has been found.')).toBeTruthy();
    expect(queryByText('widget content')).toBeNull();
  });

  it('renders the widget when every guard passes', () => {
    const { getByText } = testRender(
      <WidgetRenderContent isMissingHostEntity={false} isMissingSavedFilters={false} hasUnresolvedVariables={false} queryRef={{}}>
        <div>widget content</div>
      </WidgetRenderContent>,
    );
    expect(getByText('widget content')).toBeTruthy();
  });
});
