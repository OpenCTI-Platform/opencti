import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as middlewareLoader from '../../../../../src/database/middleware-loader';
import * as cache from '../../../../../src/database/cache';
import * as utils from '../../../../../src/utils/access';
import * as playbookUtils from '../../../../../src/modules/playbook/playbook-utils';
import * as streamHandler from '../../../../../src/database/stream/stream-handler';
import * as notificationManager from '../../../../../src/manager/notificationManager';
import * as generateMessage from '../../../../../src/database/data-changes';
import * as playbookManagerUtils from '../../../../../src/manager/playbookManager/playbookManagerUtils';
import * as entityRepresentative from '../../../../../src/database/entity-representative';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import type { BasicStoreIdentifier } from '../../../../../src/types/store';
import type { StixBundle, StixObject } from '../../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_NOTIFIER_COMPONENT, type NotifierConfiguration } from '../../../../../src/modules/playbook/components/notifier-component';
import { playbookBundleElementsToApply, type BasicStoreEntityPlaybook, type ExecutorParameters, type NodeInstance } from '../../../../../src/modules/playbook/playbook-types';
import type { StreamDataEvent } from '../../../../../src/types/event';
import { testExecutor } from '../../../../03-integration/01-database/playbook/playbookComponents/playbook-components-test-utils';

describe('PLAYBOOK_NOTIFIER_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockContext = { id: 'context' } as unknown as AuthContext;
  const mockPlaybook = { id: 'playbook-id', name: 'Test Playbook' } as unknown as BasicStoreEntityPlaybook;
  const mockSettings = { id: 'settings-id' } as unknown as BasicStoreIdentifier;
  const mockBundle = { objects: [{ id: 'obj1', type: 'indicator' } as unknown as StixObject] } as unknown as StixBundle;
  const playbookNode = {
    id: 'playbook-node-id',
    name: 'Notifier Node',
    configuration: {
      notifiers: ['notifier-1'],
      authorized_members: [{ value: 'group-1' }],
    },
  } as unknown as NodeInstance<NotifierConfiguration>;

  beforeEach(() => {
    vi.spyOn(utils, 'executionContext').mockReturnValue(mockContext);
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue(mockPlaybook);
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue(mockSettings);
    vi.spyOn(streamHandler, 'storeNotificationEvent').mockResolvedValue(undefined);
  });

  describe('executor', () => {
    describe('message generation', () => {
      const mockUser = {
        id: 'user-1',
        name: 'Alice',
        groups: [{ internal_id: 'group-1' }],
        organizations: [],
      } as unknown as AuthUser;
      const mockNotificationUser = { id: 'notif-user' } as unknown as notificationManager.NotificationUser;

      beforeEach(() => {
        vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([mockUser]);
        vi.spyOn(notificationManager, 'convertToNotificationUser').mockReturnValue(mockNotificationUser);
        vi.spyOn(playbookUtils, 'extractBundleBaseElement').mockReturnValue(mockBundle.objects[0]);
        vi.spyOn(generateMessage, 'generateCreateMessage').mockReturnValue('generated create message');
        vi.spyOn(generateMessage, 'generateDeleteMessage').mockReturnValue('generated delete message');
      });

      it('should call storeNotificationEvent with correct message when executor is called with an event in a PIR', async () => {
        vi.spyOn(playbookManagerUtils, 'isEventInPirRelationship').mockReturnValue(true);

        const mockEventPirDelete = { type: 'delete', message: 'PIR message' } as unknown as StreamDataEvent;

        const expectedNotificationEvent: notificationManager.DigestEvent = {
          version: notificationManager.EVENT_NOTIFICATION_VERSION,
          playbook_source: mockPlaybook.name,
          notification_id: playbookNode.id,
          target: mockNotificationUser,
          type: 'digest',
          data: [
            {
              notification_id: playbookNode.id,
              instance: mockBundle.objects[0],
              message: mockEventPirDelete.message,
              type: mockEventPirDelete.type,
            },
          ],
        } as unknown as notificationManager.DigestEvent;

        const result = await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: mockBundle,
          event: mockEventPirDelete,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
        expect(result).toEqual({ output_port: undefined, bundle: mockBundle });
      });

      it('should call storeNotificationEvent with correct message when event is an update when executor is called with an update event', async () => {
        vi.spyOn(playbookManagerUtils, 'isEventInPirRelationship').mockReturnValue(false);
        vi.spyOn(entityRepresentative, 'extractEntityRepresentativeName').mockReturnValue('name');
        const mockEventUpdate = { type: 'update', message: 'update message', data: { type: 'entity type' } } as unknown as StreamDataEvent;

        const expectedNotificationEvent: notificationManager.DigestEvent = {
          version: notificationManager.EVENT_NOTIFICATION_VERSION,
          playbook_source: mockPlaybook.name,
          notification_id: playbookNode.id,
          target: mockNotificationUser,
          type: 'digest',
          data: [
            {
              notification_id: playbookNode.id,
              instance: mockBundle.objects[0],
              message: `${mockEventUpdate.message} in \`name\` ${mockEventUpdate.data.type}`,
              type: mockEventUpdate.type,
            },
          ],
        } as unknown as notificationManager.DigestEvent;

        const result = await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: mockBundle,
          event: mockEventUpdate,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
        expect(result).toEqual({ output_port: undefined, bundle: mockBundle });
      });

      it('should call storeNotificationEvent with generetad create message if event type is created and not in pir', async () => {
        vi.spyOn(playbookManagerUtils, 'isEventInPirRelationship').mockReturnValue(false);

        const mockEventCreate = { type: 'create', message: 'update message', data: { type: 'entity type' } } as unknown as StreamDataEvent;

        const expectedNotificationEvent: notificationManager.DigestEvent = {
          version: notificationManager.EVENT_NOTIFICATION_VERSION,
          playbook_source: mockPlaybook.name,
          notification_id: playbookNode.id,
          target: mockNotificationUser,
          type: 'digest',
          data: [
            {
              notification_id: playbookNode.id,
              instance: mockBundle.objects[0],
              message: 'generated create message',
              type: 'create',
            },
          ],
        } as unknown as notificationManager.DigestEvent;

        await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: mockBundle,
          event: mockEventCreate,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
      });

      it('should call storeNotificationEvent with generetad delete message if event type is deleted and not in pir', async () => {
        vi.spyOn(playbookManagerUtils, 'isEventInPirRelationship').mockReturnValue(false);

        const mockEventDelete = { type: 'delete', message: 'update message', data: { type: 'entity type' } } as unknown as StreamDataEvent;

        const expectedNotificationEvent: notificationManager.DigestEvent = {
          version: notificationManager.EVENT_NOTIFICATION_VERSION,
          playbook_source: mockPlaybook.name,
          notification_id: playbookNode.id,
          target: mockNotificationUser,
          type: 'digest',
          data: [
            {
              notification_id: playbookNode.id,
              instance: mockBundle.objects[0],
              message: 'generated delete message',
              type: 'delete',
            },
          ],
        } as unknown as notificationManager.DigestEvent;

        await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: mockBundle,
          event: mockEventDelete,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
      });

      it('should call storeNotificationEvent with generetad message if event in undefined', async () => {
        const expectedNotificationEvent: notificationManager.DigestEvent = {
          version: notificationManager.EVENT_NOTIFICATION_VERSION,
          playbook_source: mockPlaybook.name,
          notification_id: playbookNode.id,
          target: mockNotificationUser,
          type: 'digest',
          data: [
            {
              notification_id: playbookNode.id,
              instance: mockBundle.objects[0],
              message: 'generated create message',
              type: 'create',
            },
          ],
        } as unknown as notificationManager.DigestEvent;

        await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: mockBundle,
          event: undefined,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
      });
    });

    describe('applyToElements resolving target users', () => {
      const MAIN_ID = 'indicator--08e64f51-e890-5bec-be34-3344746f1b0c';
      const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
      const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';
      const MAIN_AUTHOR_ID = 'author-main';
      const MALWARE_AUTHOR_ID = 'author-malware';
      const CAMPAIGN_AUTHOR_ID = 'author-campaign';

      const bundleWithMultipleObjects = {
        objects: [
          {
            id: MAIN_ID,
            type: 'indicator',
            extensions: {
              [STIX_EXT_OCTI]: {
                created_by_ref_id: MAIN_AUTHOR_ID,
              },
            },
          } as unknown as StixObject,
          {
            id: MALWARE_ID,
            type: 'malware',
            extensions: {
              [STIX_EXT_OCTI]: {
                created_by_ref_id: MALWARE_AUTHOR_ID,
              },
            },
          } as unknown as StixObject,
          {
            id: CAMPAIGN_ID,
            type: 'campaign',
            extensions: {
              [STIX_EXT_OCTI]: {
                created_by_ref_id: CAMPAIGN_AUTHOR_ID,
              },
            },
          } as unknown as StixObject,
        ],
      } as unknown as StixBundle;

      beforeEach(() => {
        vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([
          { id: MAIN_AUTHOR_ID, groups: [], organizations: [] } as unknown as AuthUser,
          { id: MALWARE_AUTHOR_ID, groups: [], organizations: [] } as unknown as AuthUser,
          { id: CAMPAIGN_AUTHOR_ID, groups: [], organizations: [] } as unknown as AuthUser,
        ]);
        vi.spyOn(notificationManager, 'convertToNotificationUser').mockImplementation((targetUser) => ({
          user_id: targetUser.id,
          user_email: `${targetUser.id}@test.local`,
          notifiers: [],
          user_service_account: false,
        }) as notificationManager.NotificationUser);
      });

      it('should resolve target users only for main object when applyToElements = only-main', async () => {
        await PLAYBOOK_NOTIFIER_COMPONENT.executor(testExecutor<NotifierConfiguration>({
          mainId: MAIN_ID,
          bundleObjects: bundleWithMultipleObjects.objects,
          configuration: {
            ...playbookNode.configuration,
            authorized_members: [{ value: 'AUTHOR' }],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledTimes(1);
        const notificationEvent = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[0][1] as notificationManager.DigestEvent;
        expect(notificationEvent.target.user_id).toEqual(MAIN_AUTHOR_ID);
      });

      it('should resolve target users from all elements when applyToElements = all-elements', async () => {
        await PLAYBOOK_NOTIFIER_COMPONENT.executor(testExecutor<NotifierConfiguration>({
          mainId: MAIN_ID,
          bundleObjects: bundleWithMultipleObjects.objects,
          configuration: {
            ...playbookNode.configuration,
            authorized_members: [{ value: 'AUTHOR' }],
            applyToElements: playbookBundleElementsToApply.allElements.value,
          },
        }));

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledTimes(3);
        const notificationEventFirstCall = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[0][1] as notificationManager.DigestEvent;
        const notificationEventSecondCall = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[1][1] as notificationManager.DigestEvent;
        const notificationEventThirdCall = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[2][1] as notificationManager.DigestEvent;
        expect(notificationEventFirstCall.target.user_id).toEqual(MAIN_AUTHOR_ID);
        expect(notificationEventSecondCall.target.user_id).toEqual(MALWARE_AUTHOR_ID);
        expect(notificationEventThirdCall.target.user_id).toEqual(CAMPAIGN_AUTHOR_ID);
      });

      it('should resolve target users from all elements except main when applyToElements = all-except-main', async () => {
        await PLAYBOOK_NOTIFIER_COMPONENT.executor(testExecutor<NotifierConfiguration>({
          mainId: MAIN_ID,
          bundleObjects: bundleWithMultipleObjects.objects,
          configuration: {
            ...playbookNode.configuration,
            authorized_members: [{ value: 'AUTHOR' }],
            applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          },
        }));

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledTimes(2);
        const notificationEventFirstCall = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[0][1] as notificationManager.DigestEvent;
        const notificationEventSecondCall = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[1][1] as notificationManager.DigestEvent;
        expect(notificationEventFirstCall.target.user_id).toEqual(MALWARE_AUTHOR_ID);
        expect(notificationEventSecondCall.target.user_id).toEqual(CAMPAIGN_AUTHOR_ID);
      });
    });
  });
});
