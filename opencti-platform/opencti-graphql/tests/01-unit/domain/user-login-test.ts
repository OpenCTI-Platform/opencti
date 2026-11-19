import { beforeEach, describe, expect, it, vi } from 'vitest';
import bcrypt from 'bcryptjs';

vi.mock('../../../src/database/engine', () => ({
  elLoadBy: vi.fn(),
}));

import { elLoadBy } from '../../../src/database/engine';
import { login } from '../../../src/domain/user';

describe('login', () => {
  const prototype = Object.prototype as Record<string, unknown>;

  beforeEach(() => {
    vi.mocked(elLoadBy).mockReset();
  });

  it('should log in a user with the password matching its own hash', async () => {
    const user = { id: 'local-user', user_email: 'local@test.com', password: bcrypt.hashSync('local-password', 4) };
    vi.mocked(elLoadBy).mockResolvedValue(user as any);
    await expect(login('local@test.com', 'local-password')).resolves.toBe(user);
  });

  it('should refuse a user without its own password even when one is set on the object prototype', async () => {
    vi.mocked(elLoadBy).mockResolvedValue({ id: 'service-account', user_email: 'service@test.com' } as any);
    prototype.password = bcrypt.hashSync('inherited-password', 4);
    try {
      await expect(login('service@test.com', 'inherited-password')).rejects.toThrow('Bad login or password');
    } finally {
      delete prototype.password;
    }
  });
});
