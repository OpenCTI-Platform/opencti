import React, { FunctionComponent } from 'react';
import { AlertsLine_node$data } from '@components/profile/__generated__/AlertsLine_node.graphql';
import { Chip } from '@filigran/design-system';
import { iconSelector } from './notificationUtils';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../../components/i18n';

const LOCAL_STORAGE_KEY = 'digest_notification';

interface DigestNotificationProps {
  notification: AlertsLine_node$data | undefined;
}

const DigestNotification: FunctionComponent<DigestNotificationProps> = ({ notification }) => {
  const { t_i18n } = useFormatter();
  const events = notification?.notification_content.map((n) => n.events.map((p) => {
    return { ...p, title: n.title };
  })).flat();

  const dataColumns: DataTableProps['dataColumns'] = {
    operation: {
      id: 'operation',
      label: 'Operation',
      percentWidth: 20,
      isSortable: false,
      render: ({ operation }) => {
        const getChipOperationSeverity = () => {
          switch (operation) {
            case 'update':
              return 'info' as const;
            case 'delete':
              return 'critical' as const;
            default:
              return 'low' as const;
          }
        };
        return (
          <Chip
            severity={getChipOperationSeverity()}
            label={t_i18n(operation)}
            style={{ float: 'left' }}
          />
        );
      },
    },
    title: {
      id: 'title',
      label: 'Entity name',
      percentWidth: 20,
      isSortable: false,
      render: ({ title }) => defaultRender(title),
    },
    message: {
      id: 'message',
      label: 'Message',
      percentWidth: 60,
      isSortable: false,
      render: ({ message }) => defaultRender(message),
    },
  };

  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      data={events}
      storageKey={`${LOCAL_STORAGE_KEY}-${notification?.id}`}
      isLocalStorageEnabled={false}
      globalCount={events ? events.length : 0}
      variant={DataTableVariant.inline}
      icon={({ operation }) => (iconSelector(operation))}
      getComputeLink={({ instance_id, entity_type }: { instance_id: string | undefined; entity_type: string | null | undefined }) => {
        if (entity_type === 'DraftWorkspace') {
          return `/dashboard/data/import/draft/${instance_id}`;
        }
        return `/dashboard/id/${instance_id}`;
      }}
    />
  );
};

export default DigestNotification;
