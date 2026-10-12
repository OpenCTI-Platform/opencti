import { describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../../../src/types/user';

const mocks = vi.hoisted(() => ({ settings: { platform_organization: 'org-platform' } as Record<string, unknown> }));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntityFromCache: vi.fn(async () => mocks.settings),
}));

const { investigationIdentityContext } = await import('../../../../src/modules/investigationRun/investigationRun-domain');

const identity = (organizations: string[]) => ({
  id: 'user-1',
  capabilities: [],
  organizations: organizations.map((id) => ({ internal_id: id })),
  user_service_account: false,
}) as unknown as AuthUser;

describe('Case Autopilot identity context', () => {
  it('reads as an authenticated request of the run identity, with its platform organization membership', async () => {
    const inside = await investigationIdentityContext('test', identity(['org-platform']), 'draft-1');
    expect(inside.user?.id).toBe('user-1');
    expect(inside.draft_context).toBe('draft-1');
    expect(inside.user_inside_platform_organization).toBe(true);
    expect((await investigationIdentityContext('test', identity(['org-other']))).user_inside_platform_organization).toBe(false);
    mocks.settings = {};
    expect((await investigationIdentityContext('test', identity(['org-other']))).user_inside_platform_organization).toBe(true);
  });
});
