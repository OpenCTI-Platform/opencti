import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>()),
  checkEnterpriseEdition: vi.fn(),
}));

import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { checkEnterpriseEdition } from '../../../../src/enterprise-edition/ee';
import { findAllEmailTemplates, findEmailTemplatesByName } from '../../../../src/modules/emailTemplate/emailTemplate-domain';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../../../../src/modules/emailTemplate/emailTemplate-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Email template domain, listing for the configuration preset', () => {
  it('lists every email template, on a platform that has the Enterprise Edition only', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([{ name: 'A' }] as never);
    expect(await findAllEmailTemplates(context, user, { orderBy: 'name' })).toEqual([{ name: 'A' }]);
    expect(fullEntitiesList).toHaveBeenCalledWith(context, user, [ENTITY_TYPE_EMAIL_TEMPLATE], { orderBy: 'name' });
    vi.mocked(checkEnterpriseEdition).mockRejectedValue(new Error('Enterprise edition is not enabled'));
    vi.mocked(fullEntitiesList).mockClear();
    await expect(findAllEmailTemplates(context, user)).rejects.toThrow('Enterprise edition is not enabled');
    expect(fullEntitiesList).not.toHaveBeenCalled();
  });

  it('finds the templates that have exactly this name: the search of the engine ignores the case, two names that differ by it are two templates', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([{ name: 'Welcome' }, { name: 'welcome' }, { name: 'Welcome' }] as never);
    expect(await findEmailTemplatesByName(context, user, 'Welcome')).toEqual([{ name: 'Welcome' }, { name: 'Welcome' }]);
    expect(fullEntitiesList).toHaveBeenCalledWith(context, user, [ENTITY_TYPE_EMAIL_TEMPLATE], {
      filters: { mode: 'and', filters: [{ key: ['name'], values: ['Welcome'] }], filterGroups: [] },
    });
  });
});
