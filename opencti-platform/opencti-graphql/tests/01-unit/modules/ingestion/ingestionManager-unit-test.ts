import { isMustExecuteIteration } from '../../../../src/manager/ingestionManager';
import { describe, expect, it } from 'vitest';

describe('Ingestion isMustExecuteIteration coverage', () => {
  // --- Cases that return true (must execute) ---

  it('should return true when last_execution_date is undefined', () => {
    const result = isMustExecuteIteration(undefined, 'PT1H');
    expect(result).toBe(true);
  });

  it('should return true when scheduling_period is empty string', () => {
    const result = isMustExecuteIteration(new Date(), '');
    expect(result).toBe(true);
  });

  it('should return true when scheduling_period is "auto"', () => {
    const result = isMustExecuteIteration(new Date(), 'auto');
    expect(result).toBe(true);
  });

  it('should return true when last_execution_date is far in the past (period elapsed)', () => {
    // 2 days ago, with a 1-day period => period has elapsed => must execute
    const twoDaysAgo = new Date(Date.now() - 2 * 86400000);
    const result = isMustExecuteIteration(twoDaysAgo, 'PT1D');
    expect(result).toBe(true);
  });

  it('should return true when last_execution_date is older than 1 hour with PT1H period', () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 3600000);
    const result = isMustExecuteIteration(twoHoursAgo, 'PT1H');
    expect(result).toBe(true);
  });

  it('should return true when last_execution_date is older than 5 minutes with PT5M period', () => {
    const tenMinutesAgo = new Date(Date.now() - 10 * 60000);
    const result = isMustExecuteIteration(tenMinutesAgo, 'PT5M');
    expect(result).toBe(true);
  });

  // --- Cases that return false (must NOT execute) ---

  it('should return false when last_execution_date is recent and within PT1D period', () => {
    // 1 hour ago with a 1-day period => still in range => must NOT execute
    const oneHourAgo = new Date(Date.now() - 3600000);
    const result = isMustExecuteIteration(oneHourAgo, 'PT1D');
    expect(result).toBe(false);
  });

  it('should return false when last_execution_date is recent and within PT1H period', () => {
    // 10 minutes ago with a 1-hour period => still in range
    const tenMinutesAgo = new Date(Date.now() - 10 * 60000);
    const result = isMustExecuteIteration(tenMinutesAgo, 'PT1H');
    expect(result).toBe(false);
  });

  it('should return false when last_execution_date is recent and within PT5M period', () => {
    // 1 minute ago with a 5-minute period => still in range
    const oneMinuteAgo = new Date(Date.now() - 60000);
    const result = isMustExecuteIteration(oneMinuteAgo, 'PT5M');
    expect(result).toBe(false);
  });

  it('should return false when last_execution_date is recent and within PT12H period', () => {
    const oneHourAgo = new Date(Date.now() - 3600000);
    const result = isMustExecuteIteration(oneHourAgo, 'PT12H');
    expect(result).toBe(false);
  });

  // --- Edge cases ---

  it('should return true when all parameters are undefined/empty (no scheduling_period, no date)', () => {
    const result = isMustExecuteIteration(undefined, '');
    expect(result).toBe(true);
  });

  it('should return true when scheduling_period is an unknown value and last_execution_date is set', () => {
    // Unknown period maps to 0ms in schedulingPeriodToMs, so isDateInRange with 0 range should be false => must execute
    const oneMinuteAgo = new Date(Date.now() - 60000);
    const result = isMustExecuteIteration(oneMinuteAgo, 'UNKNOWN');
    expect(result).toBe(true);
  });

  it('should return false when last_execution_date is exactly now with PT15M period', () => {
    const justNow = new Date();
    const result = isMustExecuteIteration(justNow, 'PT15M');
    expect(result).toBe(false);
  });

  it('should return true when last_execution_date is older than 30 minutes with PT30M period', () => {
    const fortyMinutesAgo = new Date(Date.now() - 40 * 60000);
    const result = isMustExecuteIteration(fortyMinutesAgo, 'PT30M');
    expect(result).toBe(true);
  });

  it('should return false when last_execution_date is 20 minutes ago with PT30M period', () => {
    const twentyMinutesAgo = new Date(Date.now() - 20 * 60000);
    const result = isMustExecuteIteration(twentyMinutesAgo, 'PT30M');
    expect(result).toBe(false);
  });

  it('should return true when last_execution_date is 7 hours ago with PT6H period', () => {
    const sevenHoursAgo = new Date(Date.now() - 7 * 3600000);
    const result = isMustExecuteIteration(sevenHoursAgo, 'PT6H');
    expect(result).toBe(true);
  });

  it('should return false when last_execution_date is 3 hours ago with PT6H period', () => {
    const threeHoursAgo = new Date(Date.now() - 3 * 3600000);
    const result = isMustExecuteIteration(threeHoursAgo, 'PT6H');
    expect(result).toBe(false);
  });
});
