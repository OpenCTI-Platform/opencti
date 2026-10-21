import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ThreatPulseTrendChart from './ThreatPulseTrendChart';
import ThreatPulseUniquenessMeter from './ThreatPulseUniquenessMeter';

describe('ThreatPulseTrendChart', () => {
  it('should draw one bar per week of a weekly series, under its accessible name', () => {
    testRender(<ThreatPulseTrendChart series={[0, 2, 5, 9]} label="Contributing platforms per week, last 4 weeks" />);
    const chart = screen.getByRole('img', { name: 'Contributing platforms per week, last 4 weeks' });
    expect(chart.getAttribute('data-variant')).toBe('weekly');
    expect(within(chart).getAllByTestId('threat-pulse-sparkline-bar')).toHaveLength(4);
  });

  it('should draw two weeks as a two-point indicator', () => {
    testRender(<ThreatPulseTrendChart series={[3, 6]} label="trend" />);
    expect(screen.getByTestId('threat-pulse-sparkline').getAttribute('data-variant')).toBe('two-points');
  });

  it.each([
    ['no week', []],
    ['a single week', [8]],
    ['weeks without any platform', [0, 0, 0]],
  ])('should draw nothing rather than a fake chart for %s', (_, series) => {
    testRender(<ThreatPulseTrendChart series={series} label="trend" />);
    expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
  });
});

describe('ThreatPulseUniquenessMeter', () => {
  it('should place a score of 0 on its scale and say what it means', () => {
    testRender(<ThreatPulseUniquenessMeter score={0} meaning="Held across the community: broadly shared, not specific to you." />);
    const meter = screen.getByRole('meter', { name: 'Community uniqueness' });
    expect(meter.getAttribute('aria-valuenow')).toBe('0');
    expect(meter.getAttribute('aria-valuemin')).toBe('0');
    expect(meter.getAttribute('aria-valuemax')).toBe('100');
    expect(screen.getByText('0 out of 100')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-uniqueness-meaning').textContent).toBe('Held across the community: broadly shared, not specific to you.');
  });

  it('should keep a score out of range on the scale, without a meaning line when none is given', () => {
    testRender(<ThreatPulseUniquenessMeter score={140} />);
    expect(screen.getByRole('meter', { name: 'Community uniqueness' }).getAttribute('aria-valuenow')).toBe('100');
    expect(screen.queryByTestId('threat-pulse-uniqueness-meaning')).toBeNull();
  });
});
