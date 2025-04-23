import { deepPurple, green, indigo, red } from '@mui/material/colors';
import { BellCogOutline, BellOutline, BellPlusOutline, BellRemoveOutline, FileTableBoxMultipleOutline } from 'mdi-material-ui';
import React from 'react';
import { NotificationsLine_node$data } from '@components/profile/__generated__/NotificationsLine_node.graphql';

export const colors: Record<string, string> = {
  none: green[500],
  create: green[500],
  update: deepPurple[500],
  delete: red[500],
  multiple: indigo[500],
};

export const getFirstOperation = ({ notification_content, notification_type }: Pick<NotificationsLine_node$data, 'notification_content' | 'notification_type'>) => {
  const events = notification_content.map((n) => n.events).flat();
  const firstEvent = events.at(0);
  const isDigest = notification_type === 'digest';
  return isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
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
