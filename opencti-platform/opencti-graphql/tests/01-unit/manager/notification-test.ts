import { describe, expect, it } from 'vitest';
import { isTimeTrigger, ResolvedDigest } from '../../../src/manager/notificationManager';
import { utcDate } from '../../../src/utils/format';

const digest = (period: 'hour' | 'day' | 'week' | 'month', triggerTime = ''): ResolvedDigest => {
  return {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    trigger: {
      internal_id: '',
      name: 'test notification',
      description: 'test notification',
      period,
      trigger_type: 'digest',
      trigger_time: triggerTime,
      trigger_ids: [],
      outcomes: []
    },
    users: []
  };
};

describe.concurrent('notification manager utils', () => {
  it('should notification hour trigger computed', async () => {
    expect(isTimeTrigger(digest('hour'), utcDate('2022-11-25T19:11:00.000Z'))).toEqual(false);
    expect(isTimeTrigger(digest('hour'), utcDate('2022-11-25T19:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('hour'), utcDate('2022-11-25T19:00:05.000Z'))).toEqual(true);
  });

  it('should notification day trigger computed', async () => {
    expect(isTimeTrigger(digest('day', '15:00:00.000Z'), utcDate('2022-11-25T15:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('day', '15:00:00.000Z'), utcDate('2022-10-10T15:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('day', '15:00:00.000Z'), utcDate('2024-01-01T15:00:01.001Z'))).toEqual(true);
    expect(isTimeTrigger(digest('day', '15:00:00.000Z'), utcDate('2024-01-02T15:00:02.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('day', '15:00:00.000Z'), utcDate('2024-01-01T14:00:00.000Z'))).toEqual(false);
    expect(isTimeTrigger(digest('day', '15:00:00.000Z'), utcDate('2024-01-01T15:01:00.000Z'))).toEqual(false);
  });

  it('should notification day week computed', async () => { // 1 being Monday and 7 being Sunday.
    expect(isTimeTrigger(digest('week', '1-16:00:00.000Z'), utcDate('2022-11-28T16:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('week', '1-16:00:00.000Z'), utcDate('2022-11-21T16:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('week', '3-11:00:00.000Z'), utcDate('2022-11-16T11:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('week', '1-16:00:00.000Z'), utcDate('2022-11-21T17:00:00.000Z'))).toEqual(false);
    expect(isTimeTrigger(digest('week', '1-16:00:00.000Z'), utcDate('2022-11-20T16:00:00.000Z'))).toEqual(false);
  });
  it('should notification day month computed', async () => {
    expect(isTimeTrigger(digest('month', '1-12:00:00.000Z'), utcDate('2022-04-01T12:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('month', '1-12:00:00.000Z'), utcDate('2022-01-01T12:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('month', '2-12:00:00.000Z'), utcDate('2022-12-02T12:00:00.000Z'))).toEqual(true);
    expect(isTimeTrigger(digest('month', '1-12:00:00.000Z'), utcDate('2022-12-02T12:00:00.000Z'))).toEqual(false);
  });
});
