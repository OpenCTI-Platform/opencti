import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import NewsFeedSettings from './NewsFeedSettings';

const KNOWN_TYPES = ['RESOURCE_CUSTOM_DASHBOARD', 'RESOURCE_PLAYBOOK'];

const renderSettings = (props: Partial<React.ComponentProps<typeof NewsFeedSettings>> = {}) => {
  const onSubmitField = props.onSubmitField ?? vi.fn();
  const rendered = testRender(
    <NewsFeedSettings
      availableNewsFeedTypes={props.availableNewsFeedTypes}
      unsubscribedNewsFeedTypes={props.unsubscribedNewsFeedTypes}
      onSubmitField={onSubmitField}
    />,
  );
  return { ...rendered, onSubmitField };
};

/** The global switch is always the first one, per type switches follow in order. */
const getSwitches = () => screen.getAllByRole('checkbox');

describe('NewsFeedSettings', () => {
  it('renders the global toggle', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES });
    expect(screen.getByText('Enable News Feed notifications')).toBeInTheDocument();
  });

  it('checks the global toggle when the user is not globally unsubscribed', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: [] });
    expect(getSwitches()[0]).toBeChecked();
  });

  it('unchecks the global toggle when the user is globally unsubscribed', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: ['*'] });
    expect(getSwitches()[0]).not.toBeChecked();
  });

  it('hides the per type rows when the user is globally unsubscribed', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: ['*'] });
    expect(getSwitches()).toHaveLength(1);
  });

  it('renders one row per available news feed type', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES });
    expect(getSwitches()).toHaveLength(KNOWN_TYPES.length + 1);
    expect(screen.getByText('Custom Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Playbook')).toBeInTheDocument();
  });

  it('renders only the global toggle when no news feed type is available', () => {
    renderSettings({ availableNewsFeedTypes: [] });
    expect(getSwitches()).toHaveLength(1);
  });

  it('renders only the global toggle when props are omitted', () => {
    testRender(<NewsFeedSettings onSubmitField={vi.fn()} />);
    expect(getSwitches()).toHaveLength(1);
  });

  it('checks a type toggle when the user is subscribed to it', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: [] });
    expect(getSwitches()[1]).toBeChecked();
    expect(getSwitches()[2]).toBeChecked();
  });

  it('unchecks only the type toggles the user unsubscribed from', () => {
    renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: ['RESOURCE_PLAYBOOK'] });
    expect(getSwitches()[1]).toBeChecked();
    expect(getSwitches()[2]).not.toBeChecked();
  });

  it('displays a fallback label for an unsupported news feed type', () => {
    renderSettings({ availableNewsFeedTypes: ['RESOURCE_SOMETHING_NEW'] });
    expect(screen.getByText('Unsupported type')).toBeInTheDocument();
    expect(screen.queryByText('RESOURCE_SOMETHING_NEW')).not.toBeInTheDocument();
  });

  it('unsubscribes from everything when the global toggle is turned off', async () => {
    const { user, onSubmitField } = renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: [] });
    await user.click(getSwitches()[0]);
    expect(onSubmitField).toHaveBeenCalledWith('unsubscribed_news_feed_types', ['*']);
  });

  it('resubscribes to everything when the global toggle is turned on', async () => {
    const { user, onSubmitField } = renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: ['*'] });
    await user.click(getSwitches()[0]);
    expect(onSubmitField).toHaveBeenCalledWith('unsubscribed_news_feed_types', []);
  });

  it('adds the type to the unsubscribed list when its toggle is turned off', async () => {
    const { user, onSubmitField } = renderSettings({ availableNewsFeedTypes: KNOWN_TYPES, unsubscribedNewsFeedTypes: [] });
    await user.click(getSwitches()[2]);
    expect(onSubmitField).toHaveBeenCalledWith('unsubscribed_news_feed_types', ['RESOURCE_PLAYBOOK']);
  });

  it('keeps the other unsubscribed types when a new type is turned off', async () => {
    const { user, onSubmitField } = renderSettings({
      availableNewsFeedTypes: KNOWN_TYPES,
      unsubscribedNewsFeedTypes: ['RESOURCE_CUSTOM_VIEW'],
    });
    await user.click(getSwitches()[2]);
    expect(onSubmitField).toHaveBeenCalledWith('unsubscribed_news_feed_types', ['RESOURCE_CUSTOM_VIEW', 'RESOURCE_PLAYBOOK']);
  });

  it('removes only the toggled type from the unsubscribed list when turned on', async () => {
    const { user, onSubmitField } = renderSettings({
      availableNewsFeedTypes: KNOWN_TYPES,
      unsubscribedNewsFeedTypes: ['RESOURCE_CUSTOM_DASHBOARD', 'RESOURCE_PLAYBOOK'],
    });
    await user.click(getSwitches()[1]);
    expect(onSubmitField).toHaveBeenCalledWith('unsubscribed_news_feed_types', ['RESOURCE_PLAYBOOK']);
  });
});
