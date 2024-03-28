import { describe, it } from 'vitest';
import { getLogFile } from '../../../src/modules/support/support-domain';

describe('Testing logging query', () => {
  it('should works', async () => {
    getLogFile();
  });
});
