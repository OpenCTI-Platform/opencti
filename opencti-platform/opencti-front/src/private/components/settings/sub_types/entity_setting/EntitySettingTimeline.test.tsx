import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import { EntitySettingTimelineDates } from './EntitySettingTimeline';

const DEFAULTS = ['first_adversary_activity', 'first_detection', 'first_response', 'containment', 'closure'] as const;
const switchOf = (key: string) => within(screen.getByTestId(`entity-setting-timeline-${key}`)).getByRole('switch');

describe('EntitySettingTimelineDates', () => {
  it('offers every date, the default ones on and the eradication, the recovery and the notification off', () => {
    testRender(<EntitySettingTimelineDates entityType="Case-Incident" headlineDates={DEFAULTS} onChange={vi.fn()} />);
    expect(screen.getAllByRole('switch')).toHaveLength(8);
    DEFAULTS.forEach((key) => expect(switchOf(key)).toBeChecked());
    ['eradication', 'recovery', 'notification'].forEach((key) => {
      expect(switchOf(key)).not.toBeChecked();
      expect(screen.getByTestId(`entity-setting-timeline-${key}`)).toHaveTextContent('Hidden by default');
    });
    // A case can complete its containment with a task, an incident cannot
    expect(screen.getByTestId('entity-setting-timeline-containment')).toHaveTextContent('This task completes the containment');
  });

  it('keeps the dates in the order of the timelines when one is switched on or off', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<EntitySettingTimelineDates entityType="Incident" headlineDates={['first_detection', 'closure']} onChange={onChange} />);
    await user.click(switchOf('recovery'));
    expect(onChange).toHaveBeenLastCalledWith(['first_detection', 'recovery', 'closure']);
    await user.click(switchOf('first_detection'));
    expect(onChange).toHaveBeenLastCalledWith(['closure']);
    expect(screen.getByTestId('entity-setting-timeline-containment')).not.toHaveTextContent('task');
  });

  it('never switches off the last date shown', () => {
    testRender(<EntitySettingTimelineDates entityType="Case-Rfi" headlineDates={['closure']} onChange={vi.fn()} />);
    expect(switchOf('closure')).toBeDisabled();
    expect(switchOf('containment')).toBeEnabled();
  });
});
