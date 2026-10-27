import { describe, expect, it } from 'vitest';
import { checkDateDisplayInput } from '../../../src/utils/dateDisplay';
import { EditOperation } from '../../../src/generated/graphql';

const input = (key: string, value: unknown[]) => ({ key, value, operation: EditOperation.Replace });

describe('Date display utilities: checkDateDisplayInput', () => {
  it('should accept every supported date and time format', () => {
    ['auto', 'iso'].forEach((format) => {
      expect(() => checkDateDisplayInput([input('date_format', [format])], 'date_format', 'time_format')).not.toThrow();
    });
    ['auto', 'none', 'minutes', 'seconds'].forEach((format) => {
      expect(() => checkDateDisplayInput([input('time_format', [format])], 'date_format', 'time_format')).not.toThrow();
    });
  });

  it('should ignore the inputs of other keys', () => {
    expect(() => checkDateDisplayInput([input('language', ['fr-fr'])], 'date_format', 'time_format')).not.toThrow();
  });

  it('should reject an unknown or multiple value', () => {
    expect(() => checkDateDisplayInput([input('platform_date_format', ['DD/MM/YYYY'])], 'platform_date_format', 'platform_time_format'))
      .toThrow('Unsupported date format');
    expect(() => checkDateDisplayInput([input('platform_time_format', ['minutes', 'seconds'])], 'platform_date_format', 'platform_time_format'))
      .toThrow('Unsupported time format');
    expect(() => checkDateDisplayInput([input('time_format', [])], 'date_format', 'time_format'))
      .toThrow('Unsupported time format');
  });
});
