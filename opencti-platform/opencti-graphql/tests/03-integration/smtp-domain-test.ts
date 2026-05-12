import { describe, expect, it } from 'vitest';
import { smtpIsAlive } from '../../src/database/smtp';

describe('SMTP basic and utils', () => {
  it('should smtpIsAlive run without error', async () => {
    await expect(smtpIsAlive()).resolves.not.toThrow();
  });
});
