import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { scheduleChartDraw } from './chartDrawQueue';

describe('scheduleChartDraw', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.runAllTimers();
    vi.useRealTimers();
  });

  it('draws the first chart at once, and the charts drawn with it one per task', () => {
    const draws: string[] = [];
    scheduleChartDraw(() => draws.push('first'));
    scheduleChartDraw(() => draws.push('second'));
    scheduleChartDraw(() => draws.push('third'));
    expect(draws).toEqual(['first']);
    vi.advanceTimersToNextTimer();
    expect(draws).toEqual(['first', 'second']);
    vi.advanceTimersToNextTimer();
    expect(draws).toEqual(['first', 'second', 'third']);

    // Once every chart is drawn, the next one is drawn at once
    vi.runAllTimers();
    scheduleChartDraw(() => draws.push('later'));
    expect(draws).toEqual(['first', 'second', 'third', 'later']);
  });

  it('does not draw a cancelled chart', () => {
    const draws: string[] = [];
    scheduleChartDraw(() => draws.push('first'));
    const cancel = scheduleChartDraw(() => draws.push('second'));
    scheduleChartDraw(() => draws.push('third'));
    cancel();
    vi.advanceTimersToNextTimer();
    expect(draws).toEqual(['first', 'third']);
  });
});
