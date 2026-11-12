import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/emailTemplate/emailTemplate-domain', () => ({
  addEmailTemplate: vi.fn(),
  fieldPatchEmailTemplate: vi.fn(),
  findEmailTemplatesByName: vi.fn(),
}));

import { addEmailTemplate, fieldPatchEmailTemplate, findEmailTemplatesByName } from '../../../../src/modules/emailTemplate/emailTemplate-domain';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { importEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-import';
import { emailTemplateImportSchema } from '../../../../src/modules/emailTemplate/emailTemplate-import-schema';
import { exportEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-export';
import type { BasicStoreEntityEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const configuration = {
  name: 'Welcome analyst',
  description: 'Onboarding message',
  email_object: 'Welcome to OpenCTI',
  sender_email: 'CTI team',
  template_body: '<p>Hello $user.firstname</p>',
};
const stored = { id: 'template-internal-id', standard_id: 'emailtemplate--1', creator_id: ['secret'], ...configuration } as unknown as BasicStoreEntityEmailTemplate;
const overwrite = { mode: ConfigImportMode.Overwrite };

const withExisting = (...templates: BasicStoreEntityEmailTemplate[]) => vi.mocked(findEmailTemplatesByName).mockResolvedValue(templates);

beforeEach(() => {
  vi.resetAllMocks();
  withExisting();
});

describe('Email template import schema', () => {
  it('accepts a template with or without a description, and keeps the values as they are', () => {
    expect(emailTemplateImportSchema.parse(configuration)).toEqual(configuration);
    const { description: _description, ...withoutDescription } = configuration;
    expect(emailTemplateImportSchema.parse(withoutDescription)).toEqual(withoutDescription);
    expect(emailTemplateImportSchema.parse({ ...configuration, description: null }).description).toBeNull();
    // The sender is a display name, not an address, and the body may be empty like the API allows
    expect(emailTemplateImportSchema.parse({ ...configuration, sender_email: '', template_body: '' })).toMatchObject({ sender_email: '', template_body: '' });
  });

  it('trims the values, as the engine does when it stores them', () => {
    const padded = { name: ' Welcome ', description: ' d ', email_object: ' Hi ', sender_email: ' CTI ', template_body: '<p>Hello</p>\n' };
    expect(emailTemplateImportSchema.parse(padded)).toEqual({ name: 'Welcome', description: 'd', email_object: 'Hi', sender_email: 'CTI', template_body: '<p>Hello</p>' });
  });

  it.each([
    ['no name', { ...configuration, name: undefined }],
    ['a name of one character', { ...configuration, name: 'a' }],
    ['a name of one character between spaces', { ...configuration, name: ' a ' }],
    ['a name of more than 512 characters', { ...configuration, name: 'a'.repeat(513) }],
    ['a blank name', { ...configuration, name: '   ' }],
    ['a blank email object', { ...configuration, email_object: '   ' }],
    ['an email object of one character', { ...configuration, email_object: 'a' }],
    ['no sender', { ...configuration, sender_email: undefined }],
    ['no body', { ...configuration, template_body: undefined }],
    ['a body that is not a string', { ...configuration, template_body: 12 }],
    ['an unknown key', { ...configuration, standard_id: 'emailtemplate--x' }],
  ])('refuses %s', (_name, input) => {
    expect(emailTemplateImportSchema.safeParse(input).success).toBe(false);
  });

  it('is the format of the export, so an export imports back as is', () => {
    const exported = exportEmailTemplate(stored);
    expect(exported).toEqual(configuration);
    expect(emailTemplateImportSchema.safeParse(exported).success).toBe(true);
  });

  it('leaves a missing description out of the export', () => {
    expect(exportEmailTemplate({ ...stored, description: null } as unknown as BasicStoreEntityEmailTemplate)).not.toHaveProperty('description');
  });
});

describe('Email template import schema, name length', () => {
  it('accepts a name up to 512 characters, the length the name is indexed up to, and refuses a longer one', () => {
    expect(emailTemplateImportSchema.safeParse({ ...configuration, name: 'a'.repeat(512) }).success).toBe(true);
    const tooLong = emailTemplateImportSchema.safeParse({ ...configuration, name: 'a'.repeat(513) });
    expect(tooLong.success).toBe(false);
    expect(tooLong.error?.issues[0].message).toBe('Name must have at most 512 characters');
  });
});

describe('importEmailTemplate', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await importEmailTemplate(context, user, { ...configuration, name: '', email_object: ' ' }, overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('name: Name must have at least 2 characters');
    expect(result.reason).toContain('email_object: Email object must have at least 2 characters');
    expect(findEmailTemplatesByName).not.toHaveBeenCalled();
  });

  it('finds the template by its trimmed name, the one the engine stores', async () => {
    await importEmailTemplate(context, user, { ...configuration, name: ' Welcome analyst ' }, { ...overwrite, dryRun: true });
    expect(findEmailTemplatesByName).toHaveBeenCalledWith(context, user, 'Welcome analyst');
  });

  it('finds the template by its name, as it is written', async () => {
    await importEmailTemplate(context, user, configuration, { ...overwrite, dryRun: true });
    expect(findEmailTemplatesByName).toHaveBeenCalledWith(context, user, 'Welcome analyst');
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('a template that does not exist (%s)', (mode) => {
    it('creates it', async () => {
      expect(await importEmailTemplate(context, user, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
      expect(addEmailTemplate).toHaveBeenCalledWith(context, user, configuration);
    });

    it('creates it without description when the configuration has none or a null one', async () => {
      await importEmailTemplate(context, user, { ...configuration, description: null }, { mode });
      expect(addEmailTemplate).toHaveBeenCalledWith(context, user, { ...configuration, description: undefined });
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importEmailTemplate(context, user, configuration, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(addEmailTemplate).not.toHaveBeenCalled();
    });
  });

  describe('a template that exists, overwrite', () => {
    beforeEach(() => withExisting(stored));

    it('is unchanged when the values only differ by their surrounding whitespace', async () => {
      const result = await importEmailTemplate(context, user, { ...configuration, name: ` ${configuration.name} `, template_body: `${configuration.template_body}\n` }, overwrite);
      expect(result).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
    });

    it('patches the fields that differ, and only those', async () => {
      const result = await importEmailTemplate(context, user, { ...configuration, email_object: 'Hello', template_body: '<p>Bye</p>' }, overwrite);
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(fieldPatchEmailTemplate).toHaveBeenCalledWith(context, user, stored.id, [
        { key: 'email_object', value: ['Hello'] },
        { key: 'template_body', value: ['<p>Bye</p>'] },
      ]);
      expect(addEmailTemplate).not.toHaveBeenCalled();
    });

    it('writes nothing on a dry run', async () => {
      expect(await importEmailTemplate(context, user, { ...configuration, sender_email: 'Other' }, { ...overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
      expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
    });

    it('can empty a body or a sender: an empty string is a value', async () => {
      await importEmailTemplate(context, user, { ...configuration, sender_email: '', template_body: '' }, overwrite);
      expect(fieldPatchEmailTemplate).toHaveBeenCalledWith(context, user, stored.id, [
        { key: 'sender_email', value: [''] },
        { key: 'template_body', value: [''] },
      ]);
    });

    it.each([
      ['has the same values', configuration],
      ['has no description', { ...configuration, description: undefined }],
      ['has a null description', { ...configuration, description: null }],
    ])('skips it when the configuration %s', async (_name, input) => {
      expect(await importEmailTemplate(context, user, input, overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
      expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
    });

    it('gives a template without description the one of the configuration', async () => {
      withExisting({ ...stored, description: undefined } as unknown as BasicStoreEntityEmailTemplate);
      await importEmailTemplate(context, user, configuration, overwrite);
      expect(fieldPatchEmailTemplate).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'description', value: ['Onboarding message'] }]);
    });
  });

  it('refuses a template that exists when the mode is add', async () => {
    withExisting(stored);
    expect(await importEmailTemplate(context, user, { ...configuration, template_body: 'x' }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
  });

  it.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('refuses a name that several templates have, whatever the mode (%s), and writes nothing', async (mode) => {
    withExisting(stored, { ...stored, id: 'other-internal-id' } as BasicStoreEntityEmailTemplate);
    expect(await importEmailTemplate(context, user, { ...configuration, template_body: 'x' }, { mode })).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
    expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
    expect(addEmailTemplate).not.toHaveBeenCalled();
  });

  describe('the same name twice in an import', () => {
    it.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('refuses the second item of a name (%s), which would overwrite the first, and reserves the name of the first', async (mode) => {
      const reservedNames = new Set<string>();
      const dryRun = { mode, dryRun: true, reservedNames };
      expect(await importEmailTemplate(context, user, configuration, dryRun)).toMatchObject({ status: 'created', exists: false });
      expect([...reservedNames]).toEqual(['Welcome analyst']);
      expect(await importEmailTemplate(context, user, { ...configuration, template_body: 'other' }, dryRun)).toMatchObject({ status: 'failed', code: 'duplicate', exists: false });
      expect(addEmailTemplate).not.toHaveBeenCalled();
      expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
    });

    it('reserves the name of an existing template too, and leaves the other names alone', async () => {
      vi.mocked(findEmailTemplatesByName).mockImplementation(async (_context, _user, name) => (name === stored.name ? [stored] : []));
      const reservedNames = new Set<string>();
      const dryRun = { mode: ConfigImportMode.Overwrite, dryRun: true, reservedNames };
      expect(await importEmailTemplate(context, user, { ...configuration, template_body: 'x' }, dryRun)).toMatchObject({ status: 'overwritten' });
      expect(await importEmailTemplate(context, user, { ...configuration, template_body: 'y' }, dryRun)).toMatchObject({ code: 'duplicate' });
      expect(await importEmailTemplate(context, user, { ...configuration, name: 'Another one' }, dryRun)).toMatchObject({ status: 'created', exists: false });
    });

    it('writes with no reservation: the apply of an item is not refused for the reservation of its own dry run', async () => {
      expect(await importEmailTemplate(context, user, configuration, overwrite)).toMatchObject({ status: 'created' });
      expect(addEmailTemplate).toHaveBeenCalledOnce();
    });

    it('refuses the name that a copy took too: the next item of that name would overwrite the copy', async () => {
      const reservedNames = new Set<string>();
      await importEmailTemplate(context, user, configuration, { mode: ConfigImportMode.Copy, dryRun: true, reservedNames });
      expect(await importEmailTemplate(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true, reservedNames })).toMatchObject({ code: 'duplicate' });
    });
  });

  describe('copy', () => {
    const copy = { mode: ConfigImportMode.Copy };
    const namesOf = (...names: string[]) => vi.mocked(findEmailTemplatesByName).mockImplementation(
      async (_context, _user, name) => (names.includes(name) ? [{ ...stored, name }] : []) as BasicStoreEntityEmailTemplate[],
    );

    it('creates the template under its own name when no template has it, without a conflict', async () => {
      expect(await importEmailTemplate(context, user, configuration, copy)).toEqual({ status: 'created', exists: false, configuration, reason: undefined });
      expect(addEmailTemplate).toHaveBeenCalledWith(context, user, configuration);
    });

    it('creates a copy under the first free name when the name is taken, and leaves the template untouched', async () => {
      namesOf('Welcome analyst', 'Welcome analyst (1)');
      expect(await importEmailTemplate(context, user, configuration, copy)).toMatchObject({ status: 'created', exists: true, reason: 'Added as "Welcome analyst (2)"' });
      expect(addEmailTemplate).toHaveBeenCalledWith(context, user, { ...configuration, name: 'Welcome analyst (2)' });
      expect(fieldPatchEmailTemplate).not.toHaveBeenCalled();
    });

    it('reads the name of the configuration once: it is the first candidate of the copy', async () => {
      await importEmailTemplate(context, user, configuration, copy);
      expect(findEmailTemplatesByName).toHaveBeenCalledTimes(1);
      namesOf('Welcome analyst');
      vi.mocked(findEmailTemplatesByName).mockClear();
      await importEmailTemplate(context, user, configuration, copy);
      expect(vi.mocked(findEmailTemplatesByName).mock.calls.map(([, , name]) => name)).toEqual(['Welcome analyst', 'Welcome analyst (1)']);
    });

    it('keeps the name of a copy within the 512 characters of the name', async () => {
      const name = 'a'.repeat(512);
      vi.mocked(findEmailTemplatesByName).mockImplementation(async (_context, _user, candidate) => (candidate === name ? [{ ...stored, name }] : []));
      await importEmailTemplate(context, user, { ...configuration, name }, copy);
      expect(vi.mocked(addEmailTemplate).mock.calls[0][2].name).toBe(`${'a'.repeat(508)} (1)`);
    });

    it('copies a name that several templates have: it is no ambiguity for a copy', async () => {
      vi.mocked(findEmailTemplatesByName).mockImplementation(
        async (_context, _user, name) => (name === 'Welcome analyst' ? [stored, { ...stored, id: 'other' }] : []) as BasicStoreEntityEmailTemplate[],
      );
      expect(await importEmailTemplate(context, user, configuration, copy)).toMatchObject({ status: 'created', exists: true, reason: 'Added as "Welcome analyst (1)"' });
    });

    it('is a free name for a template whose description is null', async () => {
      await importEmailTemplate(context, user, { ...configuration, description: null }, copy);
      expect(addEmailTemplate).toHaveBeenCalledWith(context, user, { ...configuration, description: undefined });
    });

    it('is refused when the first copies are all taken', async () => {
      vi.mocked(findEmailTemplatesByName).mockResolvedValue([stored]);
      expect(await importEmailTemplate(context, user, configuration, copy)).toMatchObject({ status: 'failed', code: 'name_conflict', exists: true });
      expect(addEmailTemplate).not.toHaveBeenCalled();
    });

    it('writes nothing in a dry run, and reserves the name for the next copies of the same dry run', async () => {
      namesOf('Welcome analyst');
      const reservedNames = new Set<string>();
      const dryRun = { mode: ConfigImportMode.Copy, dryRun: true, reservedNames };
      expect(await importEmailTemplate(context, user, configuration, dryRun)).toMatchObject({ status: 'created', reason: 'Added as "Welcome analyst (1)"' });
      expect(await importEmailTemplate(context, user, configuration, dryRun)).toMatchObject({ status: 'created', reason: 'Added as "Welcome analyst (2)"' });
      expect([...reservedNames]).toEqual(['Welcome analyst (1)', 'Welcome analyst (2)']);
      expect(addEmailTemplate).not.toHaveBeenCalled();
    });
  });
});
