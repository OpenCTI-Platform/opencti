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

  it('renders the widget saying why it runs no query, once granted, instead of waiting for one', () => {
    const skipped = testRender(
      <WidgetRenderContent isMissingHostEntity={false} isMissingSavedFilters={false} hasUnresolvedVariables={false} queryRef={null} isQuerySkipped>
        <div>not queried</div>
      </WidgetRenderContent>,
    );
    expect(skipped.container.textContent).toEqual('not queried');
    skipped.unmount();
    const denied = testRender(
      <WidgetRenderContent isMissingHostEntity={false} isMissingSavedFilters={false} hasUnresolvedVariables={false} queryRef={null} isQuerySkipped isGranted={false}>
        <div>not queried</div>
      </WidgetRenderContent>,
    );
    // Outside the enterprise edition, the access denied says the feature needs it
    expect(denied.container.textContent).toEqual('This feature is only available in OpenCTI Enterprise Edition.');
  });
});
