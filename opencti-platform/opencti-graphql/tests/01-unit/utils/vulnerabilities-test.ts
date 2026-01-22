import { describe, expect, it } from 'vitest';
import { getCodeValue, getFullValue, parseCvssVector, updateCvssVector, getCvssCriticity, isValidCvssVector } from '../../../src/utils/vulnerabilities';

// Mock the cvssMappings to test getCodeValue
const mockCvss2Config = {
  fullToCode: {
    AV: { Network: 'N', 'Adjacent Network': 'A', Local: 'L' },
    AC: { High: 'H', Medium: 'M', Low: 'L' },
    AU: { None: 'N', Single: 'S', Multiple: 'M' },
  },
  codeToFull: {
    AV: { N: 'Network', A: 'Adjacent Network', L: 'Local' },
    AC: { H: 'High', M: 'Medium', L: 'Low' },
    AU: { N: 'None', S: 'Single', M: 'Multiple' },
  },
};

const mockCvss3Config = {
  fullToCode: {
    AV: { Network: 'N', Adjacent: 'A', Local: 'L', Physical: 'P' },
    AC: { Low: 'L', High: 'H' },
    PR: { None: 'N', Low: 'L', High: 'H' },
  },
  codeToFull: {
    AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
    AC: { L: 'Low', H: 'High' },
    PR: { N: 'None', L: 'Low', H: 'High' },
  },
};

const mockCvss4Config = {
  fullToCode: {
    AV: { Network: 'N', Adjacent: 'A', Local: 'L', Physical: 'P' },
    AC: { Low: 'L', High: 'H' },
    AT: { None: 'N', Present: 'P' },
  },
  codeToFull: {
    AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
    AC: { L: 'Low', H: 'High' },
    AT: { N: 'None', P: 'Present' },
  },
};

describe('Vulnerabilities Utils', () => {
  describe('getCodeValue', () => {
    describe('CVSS2', () => {
      it('should return code for exact full label match', () => {
        const result = getCodeValue('AV', 'Network', mockCvss2Config as any);
        expect(result).toBe('N');
      });

      it('should return code for case-insensitive full label match', () => {
        const result = getCodeValue('AV', 'network', mockCvss2Config as any);
        expect(result).toBe('N');
      });

      it('should return code when input is already a code', () => {
        const result = getCodeValue('AV', 'N', mockCvss2Config as any);
        expect(result).toBe('N');
      });

      it('should return code for lowercase code input', () => {
        const result = getCodeValue('AV', 'n', mockCvss2Config as any);
        expect(result).toBe('N');
      });

      it('should handle Adjacent Network variations for CVSS2', () => {
        expect(getCodeValue('AV', 'Adjacent Network', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENT_NETWORK', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENT-NETWORK', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent network', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent_network', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent-network', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacentnetwork', mockCvss2Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENTNETWORK', mockCvss2Config as any)).toBe('A');
      });

      it('should not affect other metrics', () => {
        const result = getCodeValue('AC', 'High', mockCvss2Config as any);
        expect(result).toBe('H');
      });

      it('should return original value if not found', () => {
        const result = getCodeValue('AV', 'Unknown', mockCvss2Config as any);
        expect(result).toBe('Unknown');
      });

      it('should return original value if metric not in config', () => {
        const result = getCodeValue('XX', 'Test', mockCvss2Config as any);
        expect(result).toBe('Test');
      });
    });

    describe('CVSS3', () => {
      it('should handle Adjacent Network variations for CVSS3', () => {
        expect(getCodeValue('AV', 'Adjacent', mockCvss3Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENT_NETWORK', mockCvss3Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENT-NETWORK', mockCvss3Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent network', mockCvss3Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent_network', mockCvss3Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent-network', mockCvss3Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacentnetwork', mockCvss3Config as any)).toBe('A');
      });

      it('should handle other CVSS3 specific values', () => {
        expect(getCodeValue('AV', 'Physical', mockCvss3Config as any)).toBe('P');
        expect(getCodeValue('AC', 'Low', mockCvss3Config as any)).toBe('L');
      });
    });

    describe('CVSS4', () => {
      it('should handle Adjacent Network variations for CVSS4', () => {
        expect(getCodeValue('AV', 'Adjacent', mockCvss4Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENT_NETWORK', mockCvss4Config as any)).toBe('A');
        expect(getCodeValue('AV', 'ADJACENT-NETWORK', mockCvss4Config as any)).toBe('A');
        expect(getCodeValue('AV', 'adjacent network', mockCvss4Config as any)).toBe('A');
      });

      it('should handle CVSS4 specific metrics', () => {
        expect(getCodeValue('AT', 'None', mockCvss4Config as any)).toBe('N');
        expect(getCodeValue('AT', 'Present', mockCvss4Config as any)).toBe('P');
      });
    });
  });

  describe('getFullValue', () => {
    it('should return full label for code', () => {
      const result = getFullValue('AV', 'N', mockCvss2Config as any);
      expect(result).toBe('Network');
    });

    it('should return full label for case-insensitive code', () => {
      const result = getFullValue('AV', 'n', mockCvss2Config as any);
      expect(result).toBe('Network');
    });

    it('should return original value if already full label', () => {
      const result = getFullValue('AV', 'Network', mockCvss2Config as any);
      expect(result).toBe('Network');
    });

    it('should return null if value is null', () => {
      const result = getFullValue('AV', null, mockCvss2Config as any);
      expect(result).toBe(null);
    });

    it('should return original value if metric is undefined', () => {
      const result = getFullValue(undefined, 'test', mockCvss2Config as any);
      expect(result).toBe('test');
    });
  });

  describe('getCvssCriticity', () => {
    it('should return Unknown for null or undefined', () => {
      expect(getCvssCriticity(null)).toBe('Unknown');
      expect(getCvssCriticity(undefined)).toBe('Unknown');
    });

    it('should return Unknown for 0.0', () => {
      expect(getCvssCriticity(0.0)).toBe('Unknown');
    });

    it('should return LOW for scores <= 3.9', () => {
      expect(getCvssCriticity(1.0)).toBe('LOW');
      expect(getCvssCriticity(3.9)).toBe('LOW');
    });

    it('should return MEDIUM for scores <= 6.9', () => {
      expect(getCvssCriticity(4.0)).toBe('MEDIUM');
      expect(getCvssCriticity(6.9)).toBe('MEDIUM');
    });

    it('should return HIGH for scores <= 8.9', () => {
      expect(getCvssCriticity(7.0)).toBe('HIGH');
      expect(getCvssCriticity(8.9)).toBe('HIGH');
    });

    it('should return CRITICAL for scores > 8.9', () => {
      expect(getCvssCriticity(9.0)).toBe('CRITICAL');
      expect(getCvssCriticity(10.0)).toBe('CRITICAL');
    });

    it('should handle string scores', () => {
      expect(getCvssCriticity('5.5')).toBe('MEDIUM');
      expect(getCvssCriticity('9.5')).toBe('CRITICAL');
    });
  });

  describe('isValidCvssVector', () => {
    it('should validate CVSS2 vectors', () => {
      expect(isValidCvssVector('cvss2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBe(true);
      expect(isValidCvssVector('cvss2', 'AV:A/AC:M/Au:S/C:C/I:C/A:C')).toBe(true);
      expect(isValidCvssVector('cvss2', 'AV:L/AC:H/Au:M/C:N/I:N/A:N')).toBe(true);
    });

    it('should validate CVSS3 vectors', () => {
      expect(isValidCvssVector('cvss3', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(true);
      expect(isValidCvssVector('cvss3', 'CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L')).toBe(true);
    });

    it('should validate CVSS3 vectors on 3.0 version', () => {
      expect(isValidCvssVector('cvss3', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(true);
      expect(isValidCvssVector('cvss3', 'CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L/E:P/RL:T/RC:R')).toBe(true);
    });

    it('should validate CVSS4 vectors', () => {
      expect(isValidCvssVector('cvss4', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')).toBe(true);
    });

    it('should return true for empty vectors', () => {
      expect(isValidCvssVector('cvss2', null)).toBe(true);
      expect(isValidCvssVector('cvss3', undefined)).toBe(true);
      expect(isValidCvssVector('cvss4', '')).toBe(true);
    });

    it('should return false for invalid vectors', () => {
      expect(isValidCvssVector('cvss2', 'invalid')).toBe(false);
      expect(isValidCvssVector('cvss3', 'CVSS:3.1/AV:X/AC:L')).toBe(false); // Invalid AV value
      expect(isValidCvssVector('cvss3', 'CVSS:2.0/AV:N/AC:L')).toBe(false); // Wrong version prefix
    });

    it('should handle case-insensitive vectors', () => {
      expect(isValidCvssVector('cvss2', 'av:n/ac:l/au:n/c:p/i:p/a:p')).toBe(true);
      expect(isValidCvssVector('cvss3', 'CVSS:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h')).toBe(true);
    });

    it('should detect duplicate metrics', () => {
      expect(isValidCvssVector('cvss2', 'AV:N/AC:L/AV:L/C:P/I:P/A:P')).toBe(false);
    });
  });

  describe('parseCvssVector', () => {
    it('should parse CVSS2 vector correctly', () => {
      const result = parseCvssVector('cvss2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P') as any[];
      const vectorField = result.find((f) => f.key === 'x_opencti_cvss_v2_access_vector');
      expect(vectorField).toBeDefined();
      expect(vectorField.value[0]).toBe('Network');
    });

    it('should parse CVSS3 vector correctly', () => {
      const result = parseCvssVector('cvss3', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C') as any[];

      const vectorField = result.find((f) => f.key === 'x_opencti_cvss_attack_vector');
      expect(vectorField).toBeDefined();
      expect(vectorField.value[0]).toBe('Network');

      const baseScoreField = result.find((f) => f.key === 'x_opencti_cvss_base_score');
      expect(baseScoreField).toBeDefined();
      expect(baseScoreField.value[0]).toBe(9.8);

      const temporalScoreField = result.find((f) => f.key === 'x_opencti_cvss_temporal_score');
      expect(temporalScoreField).toBeDefined();
      expect(temporalScoreField.value[0]).toBe(8.5);
    });

    it('should handle empty vector', () => {
      const result = parseCvssVector('cvss2', null) as any[];
      expect(result).toBeDefined();
      expect(result.every((f) => f.value[0] === null)).toBe(true);
    });

    it('should return object when asObject is true', () => {
      const result = parseCvssVector('cvss2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', null, true) as Record<string, unknown>;
      expect(result).toBeTypeOf('object');
      expect(result.x_opencti_cvss_v2_access_vector).toBe('Network');
    });
  });

  describe('updateCvssVector', () => {
    it('should update CVSS2 vector with new values', () => {
      const updates = [
        { key: 'x_opencti_cvss_v2_access_vector', value: ['Local'] }
      ];
      const result = updateCvssVector('cvss2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', updates, null) as any[];
      const vectorField = result.find((f) => f.key === 'x_opencti_cvss_v2_vector_string');
      expect(vectorField).toBeDefined();
      expect(vectorField.value[0]).toContain('AV:L');
    });

    it('should handle Adjacent Network update in CVSS3', () => {
      const updates = [
        { key: 'x_opencti_cvss_attack_vector', value: ['ADJACENT_NETWORK'] }
      ];
      const result = updateCvssVector('cvss3', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', updates, null) as any[];
      const vectorField = result.find((f) => f.key === 'x_opencti_cvss_vector_string');
      expect(vectorField).toBeDefined();
      expect(vectorField.value[0]).toContain('AV:A');
    });

    it('should return empty object when no updates', () => {
      const result = updateCvssVector('cvss2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P', [], null);
      expect(result).toEqual({});
    });
  });
});
