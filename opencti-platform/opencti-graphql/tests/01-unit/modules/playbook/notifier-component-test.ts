import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as cache from '../../../../src/database/cache';
import * as utils from '../../../../src/utils/access';
import * as playbookUtils from '../../../../src/modules/playbook/playbook-utils';
import * as redis from '../../../../src/database/redis';
import * as notificationManager from '../../../../src/manager/notificationManager';
import * as schemaUtils from '../../../../src/schema/schemaUtils';
import * as generateMessage from '../../../../src/database/generate-message';
import * as playbookManagerUtils from '../../../../src/manager/playbookManager/playbookManagerUtils';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreIdentifier } from '../../../../src/types/store';
import type { StixBundle, StixObject } from '../../../../src/types/stix-2-1-common';
import { PLAYBOOK_NOTIFIER_COMPONENT, type NotifierConfiguration } from '../../../../src/modules/playbook/components/notifier-component';
import type { BasicStoreEntityPlaybook, ExecutorParameters, NodeInstance } from '../../../../src/modules/playbook/playbook-types';
import type { StreamDataEvent } from '../../../../src/types/event';

describe('PLAYBOOK_NOTIFIER_COMPONENT', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('executor', () => {
    const mockContext = { id: 'context' } as unknown as AuthContext;
    const mockPlaybook = { id: 'playbook-id', name: 'Test Playbook' } as unknown as BasicStoreEntityPlaybook;
    const mockSettings = { id: 'settings-id' } as unknown as BasicStoreIdentifier;
    const mockBundle = { objects: [{ id: 'obj1', type: 'indicator' } as unknown as StixObject] } as unknown as StixBundle;
    const mockUser = { id: 'user-1', name: 'Alice' } as unknown as AuthUser;
    const mockNotificationUser = { id: 'notif-user' } as unknown as notificationManager.NotificationUser;
    const playbookNode = {
      id: 'playbook-node-id',
      name: 'Notifier Node',
      configuration: {
        notifiers: ['notifier-1'],
        authorized_members: [{ value: 'group-1' }]
      }
    } as unknown as NodeInstance<NotifierConfiguration>;

    beforeEach(() => {
      vi.spyOn(utils, 'executionContext').mockReturnValue(mockContext);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue(mockPlaybook);
      vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue(mockSettings);
      vi.spyOn(playbookUtils, 'extractBundleBaseElement').mockReturnValue(mockBundle.objects[0]);
      vi.spyOn(playbookUtils, 'convertMembersToUsers').mockResolvedValue([mockUser]);
      vi.spyOn(utils, 'isUserInPlatformOrganization').mockReturnValue(true);
      vi.spyOn(utils, 'isUserCanAccessStixElement').mockResolvedValue(true);
      vi.spyOn(notificationManager, 'convertToNotificationUser').mockReturnValue(mockNotificationUser);
      vi.spyOn(schemaUtils, 'convertStixToInternalTypes').mockReturnValue('Indicator');
      vi.spyOn(generateMessage, 'generateCreateMessage').mockReturnValue('genereted message');
      vi.spyOn(redis, 'storeNotificationEvent').mockResolvedValue(undefined);
    });

    it('should call storeNotificationEvent with correct message when event is a PIR', async () => {
      vi.spyOn(playbookManagerUtils, 'isEventInPir').mockReturnValue(true);

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
        event: mockEventPirDelete
      } as unknown as ExecutorParameters<NotifierConfiguration>);

      expect(redis.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
      expect(result).toEqual({ output_port: undefined, bundle: mockBundle });
    });

    it('should skip notification if event is in PIR and type is update', async () => {
      vi.spyOn(playbookManagerUtils, 'isEventInPir').mockReturnValue(true);

      await PLAYBOOK_NOTIFIER_COMPONENT.executor({
        dataInstanceId: 'instance-id',
        playbookId: 'playbook-id',
        playbookNode,
        bundle: mockBundle,
        event: { type: 'update' } as unknown as StreamDataEvent
      } as unknown as ExecutorParameters<NotifierConfiguration>);

      expect(redis.storeNotificationEvent).not.toHaveBeenCalled();
    });

    it('should call storeNotificationEvent with generetad message is event is not a PIR', async () => {
      vi.spyOn(playbookManagerUtils, 'isEventInPir').mockReturnValue(false);

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
            message: 'genereted message',
            type: 'create',
          },
        ],
      } as unknown as notificationManager.DigestEvent;

      await PLAYBOOK_NOTIFIER_COMPONENT.executor({
        dataInstanceId: 'instance-id',
        playbookId: 'playbook-id',
        playbookNode,
        bundle: mockBundle,
        event: {} as unknown as StreamDataEvent
      } as unknown as ExecutorParameters<NotifierConfiguration>);

      expect(redis.storeNotificationEvent).toHaveBeenCalledWith(mockContext, expectedNotificationEvent);
    });
  });
});
