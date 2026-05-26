import { deepPurple, green, indigo, red } from '@mui/material/colors';
import { format, isSameDay } from 'date-fns';
import { BellCogOutline, BellOutline, BellPlusOutline, BellRemoveOutline, FileTableBoxMultipleOutline } from 'mdi-material-ui';
import React from 'react';
import { isNone } from '../../../../components/i18n';

export const colors: Record<string, string> = {
  none: green[500],
  create: green[500],
  update: deepPurple[500],
  delete: red[500],
  multiple: indigo[500],
};

export const getFirstOperation = ({ notification_content, notification_type }: {
  notification_content: ReadonlyArray<{
    events: ReadonlyArray<{ operation?: string | null }>;
  }>;
  notification_type: string;
}) => {
  const events = notification_content.map((n) => n.events).flat();
  const firstEvent = events.at(0);
  const isDigest = notification_type === 'digest';
  return isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
};

export type NotificationContentShape = {
  notification_content: ReadonlyArray<{
    title?: string | null;
    events: ReadonlyArray<{
      message?: string | null;
      instance_id?: string | null;
      operation?: string | null;
    }>;
  }>;
  notification_type: string;
  name?: string | null;
};

export type NotificationViewTarget =
  | { type: 'entity'; instanceId: string }
  | { type: 'notifications' };

export const getNotificationViewTarget = (
  notification: NotificationContentShape,
): NotificationViewTarget => {
  const events = notification.notification_content.flatMap((content) => content.events);
  const isDigest = events.length > 1 || notification.notification_type === 'digest';
  if (isDigest) {
    return { type: 'notifications' };
  }
  const firstEvent = events.at(0);
  const firstOperation = getFirstOperation(notification);
  if (
    events.length === 1
    && firstEvent?.instance_id
    && firstOperation !== 'delete'
  ) {
    return { type: 'entity', instanceId: firstEvent.instance_id };
  }
  return { type: 'notifications' };
};

export const getNotificationToastTitle = (notification: NotificationContentShape) => (
  notification.notification_content[0]?.title ?? notification.name ?? ''
);

export const getNotificationToastMessage = (notification: NotificationContentShape) => {
  const events = notification.notification_content.flatMap((content) => content.events);
  if (events.length > 1) {
    return null;
  }
  return events.at(0)?.message ?? notification.name ?? '';
};

export const formatNotificationToastTimestamp = (
  created: string | null | undefined,
  labels: {
    today: string;
    formatShortDate: (date: string) => string;
  },
): string => {
  if (isNone(created)) {
    return '';
  }
  const date = new Date(created);
  const timeStr = format(date, 'HH:mm:ss');
  if (isSameDay(date, new Date())) {
    return `${labels.today} ${timeStr}`;
  }
  return `${labels.formatShortDate(created)} ${timeStr}`;
};

export const iconSelector = (operation: string) => {
  switch (operation) {
    case 'create':
      return <BellPlusOutline style={{ color: colors[operation] }} />;
    case 'update':
      return <BellCogOutline style={{ color: colors[operation] }} />;
    case 'delete':
      return <BellRemoveOutline style={{ color: colors[operation] }} />;
    case 'multiple':
      return (
        <FileTableBoxMultipleOutline style={{ color: colors[operation] }} />
      );
    default:
      return <BellOutline style={{ color: colors[operation] }} />;
  }
};
