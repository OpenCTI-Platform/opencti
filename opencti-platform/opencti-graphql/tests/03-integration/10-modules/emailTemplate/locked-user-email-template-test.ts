import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as conf from '../../../../src/config/conf';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { deleteInternalObject } from '../../../../src/domain/internalObject';
import { addEmailTemplate, initLockedUserEmailTemplate, sendTestEmail } from '../../../../src/modules/emailTemplate/emailTemplate-domain';
import * as enterpriseEdition from '../../../../src/enterprise-edition/ee';
import * as smtp from '../../../../src/database/smtp';
import { type BasicStoreEntityEmailTemplate, ENTITY_TYPE_EMAIL_TEMPLATE } from '../../../../src/modules/emailTemplate/emailTemplate-types';
import { LOCKED_USER_EMAIL_TEMPLATE_INPUT } from '../../../../src/database/locked-user-email-template-input';
import { addFilter } from '../../../../src/utils/filtering/filtering-utils';

const { isFeatureEnabled } = conf;

// The engine matches a name without its case: the templates whose name differs only by its case are found too
const templatesWithLockedUserName = () => fullEntitiesList<BasicStoreEntityEmailTemplate>(testContext, ADMIN_USER, [ENTITY_TYPE_EMAIL_TEMPLATE], {
  filters: addFilter(undefined, 'name', LOCKED_USER_EMAIL_TEMPLATE_INPUT.name),
});
const lockedUserTemplates = async () => {
  const templates = await templatesWithLockedUserName();
  return templates.filter((template) => template.name === LOCKED_USER_EMAIL_TEMPLATE_INPUT.name);
};
const deleteLockedUserTemplates = async () => {
  for (const template of await templatesWithLockedUserName()) {
    await deleteInternalObject(testContext, ADMIN_USER, template.id, ENTITY_TYPE_EMAIL_TEMPLATE);
  }
};

describe('Built-in email template for the locked users', () => {
  beforeEach(async () => {
    await deleteLockedUserTemplates();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // The platform init creates it in the tests, where every feature flag is enabled
  afterAll(async () => {
    await deleteLockedUserTemplates();
    await initLockedUserEmailTemplate(testContext);
  });

  it('should create the template only once when the startup runs twice', async () => {
    await initLockedUserEmailTemplate(testContext);
    await initLockedUserEmailTemplate(testContext);
    const templates = await lockedUserTemplates();
    expect(templates).toHaveLength(1);
    expect(templates[0]).toMatchObject({
      name: LOCKED_USER_EMAIL_TEMPLATE_INPUT.name,
      email_object: LOCKED_USER_EMAIL_TEMPLATE_INPUT.email_object,
      template_body: LOCKED_USER_EMAIL_TEMPLATE_INPUT.template_body,
    });
  });

  it('should return the existing template instead of creating another one', async () => {
    const created = await initLockedUserEmailTemplate(testContext);
    const kept = await initLockedUserEmailTemplate(testContext);
    expect(kept?.id).toEqual(created?.id);
  });

  it('should create the template again at the next startup when it was deleted', async () => {
    await initLockedUserEmailTemplate(testContext);
    await deleteLockedUserTemplates();
    await initLockedUserEmailTemplate(testContext);
    expect(await lockedUserTemplates()).toHaveLength(1);
  });

  it('should create the template when only a template whose name differs by its case exists', async () => {
    const otherName = LOCKED_USER_EMAIL_TEMPLATE_INPUT.name.toLowerCase();
    const otherTemplate = await addEmailTemplate(testContext, ADMIN_USER, { ...LOCKED_USER_EMAIL_TEMPLATE_INPUT, name: otherName }, false);
    const created = await initLockedUserEmailTemplate(testContext);
    expect(created?.id).not.toEqual(otherTemplate.id);
    expect(created?.name).toEqual(LOCKED_USER_EMAIL_TEMPLATE_INPUT.name);
    expect(await lockedUserTemplates()).toHaveLength(1);
  });

  it('should not create the template without the feature flag', async () => {
    vi.spyOn(conf, 'isFeatureEnabled').mockImplementation((flag: string) => (flag === conf.LOCAL_AUTH_LOCKOUT_FEATURE_FLAG ? false : isFeatureEnabled(flag)));
    await initLockedUserEmailTemplate(testContext);
    expect(await lockedUserTemplates()).toHaveLength(0);
  });
  it('should show a fictional lock in a test email of the template', async () => {
    vi.spyOn(enterpriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    const sendMail = vi.spyOn(smtp, 'sendMail').mockResolvedValue(undefined);
    const template = await initLockedUserEmailTemplate(testContext);
    await sendTestEmail(testContext, ADMIN_USER, template?.id as string);
    expect(sendMail).toHaveBeenCalledOnce();
    const [{ to, html }] = sendMail.mock.calls[0];
    expect(to).toEqual(ADMIN_USER.user_email);
    expect(html).toContain('The account of <strong>jdoe</strong> (john.doe@example.com) has been locked on');
    expect(html).toMatch(/after \d+ failed authentication attempts\./);
    expect(html).toMatch(/The account is locked until (\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC|an administrator unlocks it)\./);
    expect(html).not.toContain('$');
  });
});
