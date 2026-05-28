import { MESSAGING$ } from '../../../relay/environment';
import type { NotificationContentShape } from '../profile/notifications/notificationUtils';

export type DevToastNotification = NotificationContentShape & {
  id: string;
  created: string;
  is_read: boolean;
};

export type NotificationToastSimulatorScenario = 'single' | 'digest';

export type SimulateNotificationToastPayload = {
  count?: number;
  delayMs?: number;
  scenario?: NotificationToastSimulatorScenario;
};

let mockCounter = 0;

const createMockId = () => {
  mockCounter += 1;
  return `mock-notification-${mockCounter}-${Date.now()}`;
};

const buildSingleMock = (index: number): DevToastNotification => ({
  id: createMockId(),
  name: null,
  created: new Date().toISOString(),
  is_read: false,
  notification_type: 'live',
  notification_content: [
    {
      title: index % 2 === 0
        ? 'Critical incident detected'
        : 'Zyxel vulnerability exploited by Helldown ransomware group',
      events: [
        {
          operation: 'update',
          message: index % 2 === 0
            ? 'Critical incident detected in Banking sector.'
            : 'A new activity has been detected on your platform.',
          instance_id: 'mock-instance-id',
        },
      ],
    },
  ],
});

const buildDigestMock = (): DevToastNotification => ({
  id: createMockId(),
  name: null,
  created: new Date().toISOString(),
  is_read: false,
  notification_type: 'digest',
  notification_content: [
    {
      title: 'Zyxel vulnerability exploited by Helldown ransomware group 2',
      events: [
        { operation: 'update', message: 'Event A', instance_id: 'mock-a' },
        { operation: 'create', message: 'Event B', instance_id: 'mock-b' },
      ],
    },
  ],
});

export const createMockNotificationToast = (
  scenario: NotificationToastSimulatorScenario = 'single',
  index = 0,
): DevToastNotification => (
  scenario === 'digest' ? buildDigestMock() : buildSingleMock(index)
);

export const requestSimulatedNotificationToasts = (
  payload: SimulateNotificationToastPayload = {},
) => {
  const {
    count = 1,
    delayMs = 450,
    scenario = 'single',
  } = payload;

  for (let index = 0; index < count; index += 1) {
    window.setTimeout(() => {
      MESSAGING$.simulateNotificationToast.next(
        createMockNotificationToast(scenario, index),
      );
    }, index * delayMs);
  }
};
