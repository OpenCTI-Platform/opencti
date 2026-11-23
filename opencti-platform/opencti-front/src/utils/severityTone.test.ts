import { describe, expect, it } from 'vitest';
import { cvssTone, markingTone, priorityTone, scoreTone, severityTone } from './severityTone';

describe('severityTone', () => {
  it.each([
    ['critical', 'critical'],
    ['HIGH', 'high'],
    ['medium', 'medium'],
    ['low', 'low'],
    ['unknown', 'neutral'],
    [null, 'neutral'],
  ])('maps the severity %p to the %p tone', (severity, tone) => {
    expect(severityTone(severity)).toBe(tone);
  });

  it.each([
    ['P1', 'critical'],
    ['P2', 'high'],
    ['P3', 'medium'],
    ['P4', 'low'],
    ['P9', 'neutral'],
  ])('maps the priority %p to the %p tone', (priority, tone) => {
    expect(priorityTone(priority)).toBe(tone);
  });

  it.each([
    [0, 'low'],
    [20, 'low'],
    [21, 'info'],
    [50, 'info'],
    [75, 'high'],
    [100, 'critical'],
    [101, 'neutral'],
  ])('keeps the score bands: %p is %p', (score, tone) => {
    expect(scoreTone(score)).toBe(tone);
  });

  it.each([
    [0, 'neutral'],
    [3, 'low'],
    [5, 'info'],
    [7, 'high'],
    [9, 'critical'],
    [9.8, 'critical'],
    [10, 'critical'],
    [10.5, 'neutral'],
  ])('keeps the CVSS bands: %p is %p', (score, tone) => {
    expect(cvssTone(score)).toBe(tone);
  });

  it('gives the predefined markings the same tones as OpenAEV and OpenCRQ', () => {
    expect(markingTone('TLP:RED')).toBe('critical');
    expect(markingTone('PAP:RED')).toBe('critical');
    expect(markingTone('TLP:AMBER+STRICT')).toBe('high');
    expect(markingTone('TLP:GREEN')).toBe('low');
    expect(markingTone('TLP:CLEAR')).toBe('neutral');
    expect(markingTone('SF')).toBe('info');
    expect(markingTone('NONE')).toBeNull();
  });

  it('leaves a custom marking to its administrator colour', () => {
    expect(markingTone('Internal: project X')).toBeUndefined();
  });
});
