import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntSchedulePreview from './HuntSchedulePreview';
import useHuntMinScheduleInterval from './useHuntMinScheduleInterval';

vi.mock('./useHuntMinScheduleInterval', () => ({ default: vi.fn() }));

describe('HuntSchedulePreview', () => {
  beforeEach(() => {
    vi.mocked(useHuntMinScheduleInterval).mockReturnValue(15);
  });

  it('describes a manual hunt', () => {
    testRender(<HuntSchedulePreview schedule="manual" />);
    expect(screen.getByTestId('hunt-schedule-preview')).toHaveTextContent('Manual, runs only when started');
  });

  it('describes a standing hunt', () => {
    testRender(<HuntSchedulePreview schedule="standing" />);
    expect(screen.getByTestId('hunt-schedule-preview')).toHaveTextContent('Standing, runs when matching knowledge changes');
  });

  it('describes a daily cron and lists its next runs', () => {
    testRender(<HuntSchedulePreview schedule="30 6 * * *" />);
    const preview = screen.getByTestId('hunt-schedule-preview');
    expect(preview).toHaveTextContent('Every day at 06:30 UTC');
    expect(preview).toHaveTextContent('Next runs');
  });

  it('rejects a cron firing more often than the minimum interval', () => {
    testRender(<HuntSchedulePreview schedule="*/5 * * * *" />);
    expect(screen.getByTestId('hunt-schedule-preview')).toHaveTextContent('A hunt cannot run more than once every 15 minutes');
  });

  it('applies the minimum interval configured on the platform', () => {
    vi.mocked(useHuntMinScheduleInterval).mockReturnValue(60);
    testRender(<HuntSchedulePreview schedule="*/30 * * * *" />);
    expect(screen.getByTestId('hunt-schedule-preview')).toHaveTextContent('A hunt cannot run more than once every 60 minutes');
  });

  it('rejects an invalid cron expression', () => {
    testRender(<HuntSchedulePreview schedule="every tuesday" />);
    expect(screen.getByTestId('hunt-schedule-preview')).toHaveTextContent('Invalid cron expression');
    expect(screen.queryByText(/Next runs/)).not.toBeInTheDocument();
  });

  it('announces its updates to assistive technologies', () => {
    testRender(<HuntSchedulePreview schedule="manual" />);
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
  });
});
