import { describe, expect, it } from 'vitest';
import { getDependencyLabel, toDisplayedDependencies } from './SettingsDependencies';

const base = [
  { name: 'Search engine', version: 'Elk - 8.19.16' },
  { name: 'RabbitMQ', version: '4.3.4' },
  { name: 'Redis', version: '8.8.0' },
];

describe('toDisplayedDependencies', () => {
  it('hides XTM One until it is registered', () => {
    expect(toDisplayedDependencies([...base, { name: 'XTM-One', version: 'Not connected' }])).toEqual(base);
  });

  it('shows XTM One with its version once registered', () => {
    const registered = { name: 'XTM-One', version: '2.4.0' };
    expect(toDisplayedDependencies([...base, registered])).toEqual([...base, registered]);
  });

  it('keeps any other service whatever its version', () => {
    const disconnected = { name: 'Redis', version: 'Not connected' };
    expect(toDisplayedDependencies([disconnected])).toEqual([disconnected]);
  });
});

describe('getDependencyLabel', () => {
  const translate = (key: string) => (key === 'Search engine' ? 'Moteur de recherche' : key);

  it('writes XTM One as the product name, untranslated', () => {
    expect(getDependencyLabel('XTM-One', translate)).toBe('XTM One');
  });

  it('translates the other service names', () => {
    expect(getDependencyLabel('Search engine', translate)).toBe('Moteur de recherche');
    expect(getDependencyLabel('Redis', translate)).toBe('Redis');
  });
});
