import { describe, expect, it } from 'vitest';
import { normalizeTelemetryTags } from '../../../src/telemetry/TelemetryMeterManager';

describe('Telemetry tags normalization', () => {
  it('should return an empty string when no tags are configured', () => {
    expect(normalizeTelemetryTags(undefined)).toEqual('');
    expect(normalizeTelemetryTags(null)).toEqual('');
    expect(normalizeTelemetryTags('')).toEqual('');
    expect(normalizeTelemetryTags('   ')).toEqual('');
    expect(normalizeTelemetryTags(' , ,, ')).toEqual('');
  });
  it('should trim, lowercase, dedupe and sort tags into a canonical string', () => {
    expect(normalizeTelemetryTags('saas')).toEqual('saas');
    expect(normalizeTelemetryTags('saas,eu-west')).toEqual('eu-west,saas');
    expect(normalizeTelemetryTags('  EU-West ,SAAS, saas,, ')).toEqual('eu-west,saas');
    expect(normalizeTelemetryTags('b,a,c,a')).toEqual('a,b,c');
  });
});
