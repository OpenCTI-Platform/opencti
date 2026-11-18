import { deepPurple, green, indigo, orange, red } from '@mui/material/colors';
import { BellAlertOutline, BellCheckOutline, BellCogOutline, BellOutline, BellPlusOutline, BellRemoveOutline, FileTableBoxMultipleOutline } from 'mdi-material-ui';
import React from 'react';
import { AlertsLine_node$data } from '@components/profile/__generated__/AlertsLine_node.graphql';
import type { ChipSeverity } from '@filigran/design-system';
import { getHealthDisplay } from '@components/data/connectors/ingestionHealthDisplay';
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

// Same tone for an operation in the notifications list and in the details of a digest
// Event type is categorical, so the tone carries the distinction without asserting a level:
// create -> low, update -> info, delete -> critical, several at once -> medium.
// Ingestion health transitions follow the health chip (getHealthDisplay), recovered -> low.
export const operationSeverity = (operation: string): ChipSeverity => {
  const health = getHealthDisplay(operation);
  if (health) return health.chip;
  switch (operation) {
    case 'update':
      return 'info';
    case 'delete':
      return 'critical';
    case 'multiple':
      return 'medium';
    default:
      return 'low';
  }
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
