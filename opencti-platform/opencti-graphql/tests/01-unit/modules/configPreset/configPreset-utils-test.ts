import { describe, expect, it } from 'vitest';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import { buildConfigPresetExportMessage, buildConfigPresetFileName, sanitizeBundleName } from '../../../../src/modules/configPreset/configPreset-utils';

describe('Config preset naming', () => {
  it('sanitizes the bundle name', () => {
    expect(sanitizeBundleName(undefined)).toBeNull();
    expect(sanitizeBundleName('   ')).toBeNull();
    expect(sanitizeBundleName('<script>alert(1)</script>')).toBe('scriptalert(1)script');
    expect(sanitizeBundleName('Prod\n\tbundle‮  2026')).toBe('Prodbundle 2026');
    expect(sanitizeBundleName('Préréglage SOC_v1.2-(EU)')).toBe('Préréglage SOC_v1.2-(EU)');
    expect(sanitizeBundleName('a'.repeat(100))).toHaveLength(80);
  });

  it('keeps the combining marks and joiners of non-Latin scripts', () => {
    // Hindi: virama and vowel signs are combining marks
    expect(sanitizeBundleName('नमस्ते दुनिया')).toBe('नमस्ते दुनिया');
    // Persian: the zero-width non-joiner is part of the word
    expect(sanitizeBundleName('می‌خواهم')).toBe('می‌خواهم');
    // A decomposed accent is composed
    expect(sanitizeBundleName('Pre\u0301re\u0301glage')).toBe('Pr\u00e9r\u00e9glage');
  });

  it('cuts the bundle name at 80 characters without splitting a character or leaving a space', () => {
    const astral = '\u{1D49C}';
    expect(sanitizeBundleName(`${'a'.repeat(79)}${astral}bc`)).toBe(`${'a'.repeat(79)}${astral}`);
    expect(sanitizeBundleName(`${'a'.repeat(79)} bc`)).toBe('a'.repeat(79));
  });

  it('puts the UTC date, time and platform version in the zip name', () => {
    expect(buildConfigPresetFileName(new Date('2026-01-02T23:59:58.999Z'))).toBe(`opencti-config-20260102-235958-${PLATFORM_VERSION}.zip`);
  });

  it('keeps the zip name in UTC whatever the time zone of the platform', () => {
    const previousTimeZone = process.env.TZ;
    process.env.TZ = 'Pacific/Kiritimati';
    try {
      const date = new Date('2026-01-02T23:59:58.999Z');
      // UTC+14: the local day is already the next one
      expect(date.getDate()).toBe(3);
      expect(buildConfigPresetFileName(date)).toBe(`opencti-config-20260102-235958-${PLATFORM_VERSION}.zip`);
    } finally {
      if (previousTimeZone === undefined) {
        delete process.env.TZ;
      } else {
        process.env.TZ = previousTimeZone;
      }
    }
  });
});

describe('Config preset export activity message', () => {
  it('names the file and the number of items exported per type', () => {
    const message = buildConfigPresetExportMessage({
      path: 'config_preset/0b5c1e9e-4b0a-4f37-9a43-1f1c2b7c9d10',
      file_name: 'opencti-config-20261014-090507-7.0.0.zip',
      input: {
        entity_types: ['platform', 'messages'],
        counts: { platform: 1, messages: 2 },
        items: { platform: ['platform'], messages: ['banner', 'login'] },
      },
    });
    expect(message).toBe('exports the configuration preset `opencti-config-20261014-090507-7.0.0.zip` (platform: 1, messages: 2)');
  });
});
