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
import { PLAYBOOK_NOTIFIER_COMPONENT, type NotifierConfiguration } from '../../../../../src/modules/playbook/components/notifier-component';
import type { BasicStoreEntityPlaybook, ExecutorParameters, NodeInstance } from '../../../../../src/modules/playbook/playbook-types';
import type { StreamDataEvent } from '../../../../../src/types/event';

describe('PLAYBOOK_NOTIFIER_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const mockContext = { id: 'context' } as unknown as AuthContext;
  const mockPlaybook = { id: 'playbook-id', name: 'Test Playbook' } as unknown as BasicStoreEntityPlaybook;
  const mockSettings = { id: 'settings-id' } as unknown as BasicStoreIdentifier;
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
    vi.spyOn(utils, 'isUserInPlatformOrganization').mockReturnValue(true);
    vi.spyOn(utils, 'checkUserCanAccessStixElement').mockReturnValue(true);
  });

  describe('executor', () => {
    describe('message generation', () => {
      const mockBundle = { objects: [{ id: 'obj1', type: 'indicator' } as unknown as StixObject] } as unknown as StixBundle;
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

    describe('access-based STIX filtering', () => {
      const bundleWithTwoObjects = {
        objects: [
          { id: 'indicator--1', type: 'indicator' } as unknown as StixObject,
          { id: 'malware--1', type: 'malware' } as unknown as StixObject,
        ],
      } as unknown as StixBundle;

      const mockUser = {
        id: 'user-1',
        name: 'Alice',
        groups: [{ internal_id: 'group-1' }],
        organizations: [],
      } as unknown as AuthUser;

      beforeEach(() => {
        vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue([mockUser]);
        vi.spyOn(notificationManager, 'convertToNotificationUser').mockReturnValue({ id: 'notif-user' } as unknown as notificationManager.NotificationUser);
        vi.spyOn(playbookUtils, 'extractBundleBaseElement').mockReturnValue(bundleWithTwoObjects.objects[0]);
        vi.spyOn(generateMessage, 'generateCreateMessage').mockReturnValue('generated create message');
      });

      it('should include only accessible elements in notification data', async () => {
        vi.spyOn(utils, 'checkUserCanAccessStixElement')
          .mockReturnValueOnce(true)
          .mockReturnValueOnce(false);

        await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: bundleWithTwoObjects,
          event: undefined,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).toHaveBeenCalledTimes(1);
        const notificationEvent = vi.mocked(streamHandler.storeNotificationEvent).mock.calls[0][1] as notificationManager.DigestEvent;
        expect(notificationEvent.data).toHaveLength(1);
        expect(notificationEvent.data[0].instance.id).toEqual('indicator--1');
      });

      it('should skip notification when user cannot access any bundle object', async () => {
        vi.spyOn(utils, 'checkUserCanAccessStixElement').mockReturnValue(false);

        await PLAYBOOK_NOTIFIER_COMPONENT.executor({
          dataInstanceId: 'instance-id',
          playbookId: 'playbook-id',
          playbookNode,
          bundle: bundleWithTwoObjects,
          event: undefined,
        } as unknown as ExecutorParameters<NotifierConfiguration>);

        expect(streamHandler.storeNotificationEvent).not.toHaveBeenCalled();
      });
    });
  });
});
