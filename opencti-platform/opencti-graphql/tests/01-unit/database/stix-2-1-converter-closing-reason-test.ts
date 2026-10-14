import { describe, it, expect } from 'vitest';
import '../../../src/modules/index';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import type { StixIncident } from '../../../src/types/stix-2-1-sdo';
import { INCIDENT_INSTANCE } from './stix-2-0-converter-fixtures/SDOs/threats/incident';

describe('STIX 2.1 converter - closing reason', () => {
  it('should expose the closing reason in the OpenCTI extension', () => {
    const stix = convertStoreToStix_2_1({ ...INCIDENT_INSTANCE, x_opencti_closing_reason: 'false-positive' } as any) as StixIncident;
    expect(stix.extensions[STIX_EXT_OCTI].closing_reason).toBe('false-positive');
  });

  it('should omit the closing reason when the entity has none', () => {
    const stix = convertStoreToStix_2_1({ ...INCIDENT_INSTANCE, x_opencti_closing_reason: undefined } as any) as StixIncident;
    expect(stix.extensions[STIX_EXT_OCTI]).not.toHaveProperty('closing_reason');
  });
});
