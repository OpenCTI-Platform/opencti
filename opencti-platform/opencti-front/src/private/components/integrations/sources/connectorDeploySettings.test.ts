import { describe, expect, it } from 'vitest';
import { deploySettingsValidation, deploySettingValues } from './connectorDeploySettings';

const t = (message: string) => message;

const settings = [
  { key: 'API_KEY', type: 'string', secret: true },
  { key: 'NAME', type: 'string', secret: false },
  { key: 'INTERVAL', type: 'integer', secret: false },
  { key: 'RATIO', type: 'number', secret: false },
  { key: 'ENABLED', type: 'boolean', secret: false },
];

const valid = { API_KEY: ' valid-password ', NAME: 'feed', INTERVAL: '60', RATIO: '0.5', ENABLED: false };

describe('deploySettingsValidation', () => {
  const schema = deploySettingsValidation(settings, t);

  it('accepts whole numbers for integer settings and decimals for number settings', async () => {
    await expect(schema.isValid(valid)).resolves.toBe(true);
  });

  it('rejects a fractional value for an integer setting', async () => {
    await expect(schema.validate({ ...valid, INTERVAL: '1.5' })).rejects.toThrow('This field must be an integer');
  });

  it('rejects a value that is not a number for a numeric setting', async () => {
    await expect(schema.validate({ ...valid, RATIO: 'half' })).rejects.toThrow('This field must be a number');
  });

  it('requires a non-secret text setting to hold more than spaces', async () => {
    await expect(schema.validate({ ...valid, NAME: '   ' })).rejects.toThrow('This field is required');
  });

  it('requires a secret setting', async () => {
    await expect(schema.validate({ ...valid, API_KEY: '' })).rejects.toThrow('This field is required');
  });
});

describe('deploySettingValues', () => {
  it('sends a secret exactly as entered and the other values without their surrounding spaces', () => {
    expect(deploySettingValues(settings, { API_KEY: ' valid-password ', NAME: ' feed ', INTERVAL: ' 60 ', RATIO: '0.5', ENABLED: true })).toEqual([
      { key: 'API_KEY', value: ' valid-password ' },
      { key: 'NAME', value: 'feed' },
      { key: 'INTERVAL', value: '60' },
      { key: 'RATIO', value: '0.5' },
      { key: 'ENABLED', value: 'true' },
    ]);
  });

  it('sends a numeric value validated in another notation as the decimal number it stands for', async () => {
    const schema = deploySettingsValidation(settings, t);
    const entered = { ...valid, INTERVAL: '1e3', RATIO: '2.5e-1' };
    await expect(schema.isValid(entered)).resolves.toBe(true);
    const sent = (input: Record<string, string | boolean>) => deploySettingValues(settings, input).filter(({ key }) => key === 'INTERVAL' || key === 'RATIO');
    expect(sent(entered)).toEqual([{ key: 'INTERVAL', value: '1000' }, { key: 'RATIO', value: '0.25' }]);
    expect(sent({ ...valid, INTERVAL: '0x10', RATIO: '.5' })).toEqual([{ key: 'INTERVAL', value: '16' }, { key: 'RATIO', value: '0.5' }]);
    expect(sent({ ...valid, INTERVAL: '1 000', RATIO: '60.0' })).toEqual([{ key: 'INTERVAL', value: '1000' }, { key: 'RATIO', value: '60' }]);
    expect(sent({ ...valid, INTERVAL: '1e21' })[0]).toEqual({ key: 'INTERVAL', value: '1000000000000000000000' });
  });
});
