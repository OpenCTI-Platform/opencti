import { describe, it, expect, vi, beforeEach } from 'vitest';

// playbook-utils imports PLAYBOOK_INTERNAL_DATA_CRON from playbook-components which evaluates
// the full component registry at module load time, triggering initialization errors in unit tests.
vi.mock('../../../../../src/modules/playbook/playbook-components', () => ({
  PLAYBOOK_INTERNAL_DATA_CRON: { id: 'PLAYBOOK_INTERNAL_DATA_CRON' },
}));

import * as cache from '../../../../../src/database/cache';
import * as utils from '../../../../../src/utils/access';
import * as userDomain from '../../../../../src/domain/user';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import type { StixBundle, StixObject } from '../../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT, type SendEmailTemplateConfiguration } from '../../../../../src/modules/playbook/components/send-email-template-component';
import { playbookBundleElementsToApply, type NodeInstance } from '../../../../../src/modules/playbook/playbook-types';
import { testExecutor } from '../../../../03-integration/01-database/playbook/playbookComponents/playbook-components-test-utils';
import { ACCOUNT_STATUS_ACTIVE } from '../../../../../src/config/conf';

describe('PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockContext = { id: 'context' } as unknown as AuthContext;
  const mockEmail = 'template@email.io';

  const playbookNode = {
    id: 'playbook-node-id',
    name: 'Send Email Node',
    configuration: {
      email_template: mockEmail,
    },
  } as unknown as NodeInstance<SendEmailTemplateConfiguration>;

  beforeEach(() => {
    vi.spyOn(utils, 'executionContext').mockReturnValue(mockContext);
    vi.spyOn(userDomain, 'sendEmailToUser').mockResolvedValue(true);
  });

  describe('applyToElements resolving target users', () => {
    const MAIN_ID = 'indicator--08e64f51-e890-5bec-be34-3344746f1b0c';
    const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
    const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';
    const MAIN_CREATOR_ID = 'creator-main';
    const MALWARE_CREATOR_ID = 'creator-malware';
    const CAMPAIGN_CREATOR_ID = 'creator-campaign';

    const bundleWithMultipleObjects = {
      objects: [
        {
          id: MAIN_ID,
          type: 'indicator',
          extensions: {
            [STIX_EXT_OCTI]: {
              creator_ids: [MAIN_CREATOR_ID],
            },
          },
        } as unknown as StixObject,
        {
          id: MALWARE_ID,
          type: 'malware',
          extensions: {
            [STIX_EXT_OCTI]: {
              creator_ids: [MALWARE_CREATOR_ID],
            },
          },
        } as unknown as StixObject,
        {
          id: CAMPAIGN_ID,
          type: 'campaign',
          extensions: {
            [STIX_EXT_OCTI]: {
              creator_ids: [CAMPAIGN_CREATOR_ID],
            },
          },
        } as unknown as StixObject,
      ],
    } as unknown as StixBundle;

    beforeEach(() => {
      vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
        { id: MAIN_CREATOR_ID, groups: [], organizations: [], user_service_account: false, account_status: ACCOUNT_STATUS_ACTIVE } as unknown as AuthUser,
        { id: MALWARE_CREATOR_ID, groups: [], organizations: [], user_service_account: false, account_status: ACCOUNT_STATUS_ACTIVE } as unknown as AuthUser,
        { id: CAMPAIGN_CREATOR_ID, groups: [], organizations: [], user_service_account: false, account_status: ACCOUNT_STATUS_ACTIVE } as unknown as AuthUser,
      ]);
    });

    it('should send email only for main element when applyToElements = only-main', async () => {
      await PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT.executor(testExecutor<SendEmailTemplateConfiguration>({
        mainId: MAIN_ID,
        bundleObjects: bundleWithMultipleObjects.objects,
        configuration: {
          ...playbookNode.configuration,
          targets: [{ value: 'CREATORS' }],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(userDomain.sendEmailToUser).toHaveBeenCalledTimes(1);
      const sendEmailToUserInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[0][2];
      expect(sendEmailToUserInput).toEqual({ target_user_id: MAIN_CREATOR_ID, email_template_id: mockEmail });
    });

    it('should send email for all elements when applyToElements = all-elements', async () => {
      await PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT.executor(testExecutor<SendEmailTemplateConfiguration>({
        mainId: MAIN_ID,
        bundleObjects: bundleWithMultipleObjects.objects,
        configuration: {
          ...playbookNode.configuration,
          targets: [{ value: 'CREATORS' }],
          applyToElements: playbookBundleElementsToApply.allElements.value,
        },
      }));

      expect(userDomain.sendEmailToUser).toHaveBeenCalledTimes(3);
      const sendEmailToUserFirstInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[0][2];
      const sendEmailToUserSecondInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[1][2];
      const sendEmailToUserthirdInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[2][2];
      expect(sendEmailToUserFirstInput).toEqual({ target_user_id: MAIN_CREATOR_ID, email_template_id: mockEmail });
      expect(sendEmailToUserSecondInput).toEqual({ target_user_id: MALWARE_CREATOR_ID, email_template_id: mockEmail });
      expect(sendEmailToUserthirdInput).toEqual({ target_user_id: CAMPAIGN_CREATOR_ID, email_template_id: mockEmail });
    });

    it('should send email only for non-main elements when applyToElements = all-except-main', async () => {
      await PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT.executor(testExecutor<SendEmailTemplateConfiguration>({
        mainId: MAIN_ID,
        bundleObjects: bundleWithMultipleObjects.objects,
        configuration: {
          ...playbookNode.configuration,
          targets: [{ value: 'CREATORS' }],
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
        },
      }));

      expect(userDomain.sendEmailToUser).toHaveBeenCalledTimes(2);
      const sendEmailToUserFirstInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[0][2];
      const sendEmailToUserSecondInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[1][2];
      expect(sendEmailToUserFirstInput).toEqual({ target_user_id: MALWARE_CREATOR_ID, email_template_id: mockEmail });
      expect(sendEmailToUserSecondInput).toEqual({ target_user_id: CAMPAIGN_CREATOR_ID, email_template_id: mockEmail });
    });

    it('should not send email twice to the same creator when multiple elements share the same creator and applyToElements = all-elements', async () => {
      const ATTACK_PATTERN_ID = 'attack-pattern--09bd862a-70c8-55ae-ac7d-3344746f1b0c';
      const bundleWithSameCreator = {
        objects: [
          ...bundleWithMultipleObjects.objects,
          {
            id: ATTACK_PATTERN_ID,
            type: 'attack-pattern',
            extensions: {
              [STIX_EXT_OCTI]: {
                creator_ids: [MAIN_CREATOR_ID],
              },
            },
          } as unknown as StixObject,
        ],
      } as unknown as StixBundle;

      await PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT.executor(testExecutor<SendEmailTemplateConfiguration>({
        mainId: MAIN_ID,
        bundleObjects: bundleWithSameCreator.objects,
        configuration: {
          ...playbookNode.configuration,
          targets: [{ value: 'CREATORS' }],
          applyToElements: playbookBundleElementsToApply.allElements.value,
        },
      }));

      expect(userDomain.sendEmailToUser).toHaveBeenCalledTimes(3);
      const sendEmailToUserFirstInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[0][2];
      const sendEmailToUserSecondInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[1][2];
      const sendEmailToUserthirdInput = vi.mocked(userDomain.sendEmailToUser).mock.calls[2][2];
      expect(sendEmailToUserFirstInput).toEqual({ target_user_id: MAIN_CREATOR_ID, email_template_id: mockEmail });
      expect(sendEmailToUserSecondInput).toEqual({ target_user_id: MALWARE_CREATOR_ID, email_template_id: mockEmail });
      expect(sendEmailToUserthirdInput).toEqual({ target_user_id: CAMPAIGN_CREATOR_ID, email_template_id: mockEmail });
    });
  });
});
