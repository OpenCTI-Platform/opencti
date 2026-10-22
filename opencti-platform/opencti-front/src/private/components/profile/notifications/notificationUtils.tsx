import { deepPurple, green, indigo, orange, red } from '@mui/material/colors';
import { BellAlertOutline, BellCheckOutline, BellCogOutline, BellOutline, BellPlusOutline, BellRemoveOutline, FileTableBoxMultipleOutline } from 'mdi-material-ui';
import React from 'react';
import { AlertsLine_node$data } from '@components/profile/__generated__/AlertsLine_node.graphql';
import { resolveLink } from '../../../../utils/Entity';

export const colors: Record<string, string> = {
  none: green[500],
  create: green[500],
  update: deepPurple[500],
  delete: red[500],
  multiple: indigo[500],
  // ingestion health transitions
  critical: red[500],
  degraded: orange[500],
  recovered: green[500],
};

export const getFirstOperation = ({ notification_content, notification_type }: Pick<AlertsLine_node$data, 'notification_content' | 'notification_type'>) => {
  const events = notification_content.map((n) => n.events).flat();
  const firstEvent = events.at(0);
  const isDigest = notification_type === 'digest';
  return isDigest ? 'multiple' : (firstEvent?.operation ?? 'none');
};

// Not STIX objects: /dashboard/id cannot resolve them, link to their own page instead
const NON_STIX_LINKED_TYPES = ['DraftWorkspace', 'Connector', 'Sync', 'IngestionRss', 'IngestionTaxii', 'IngestionTaxiiCollection', 'IngestionCsv', 'IngestionJson'];

export const computeNotificationLink = (instanceId: string, entityType: string | null | undefined) => {
  if (entityType && NON_STIX_LINKED_TYPES.includes(entityType)) {
    return `${resolveLink(entityType)}/${instanceId}`;
  }
  return `/dashboard/id/${instanceId}`;
};

export const iconSelector = (operation: string) => {
  switch (operation) {
    case 'create':
      return <BellPlusOutline style={{ color: colors[operation] }} />;
    case 'update':
      return <BellCogOutline style={{ color: colors[operation] }} />;
    case 'delete':
      return <BellRemoveOutline style={{ color: colors[operation] }} />;
    case 'critical':
    case 'degraded':
      return <BellAlertOutline style={{ color: colors[operation] }} />;
    case 'recovered':
      return <BellCheckOutline style={{ color: colors[operation] }} />;
    case 'multiple':
      return (
        <FileTableBoxMultipleOutline style={{ color: colors[operation] }} />
      );
    default:
      return <BellOutline style={{ color: colors[operation] }} />;
  }
};
