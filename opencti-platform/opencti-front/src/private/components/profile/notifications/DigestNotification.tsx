import React, { FunctionComponent } from 'react';
import { NotificationsLine_node$data } from '@components/profile/__generated__/NotificationsLine_node.graphql';
import Chip from '@mui/material/Chip';
import { deepPurple, green, red } from '@mui/material/colors';
import { iconSelector } from './notificationUtils';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { hexToRGB } from '../../../../utils/Colors';
import { useFormatter } from '../../../../components/i18n';

const LOCAL_STORAGE_KEY = 'digest_notification';

interface DigestNotificationProps {
  notification: NotificationsLine_node$data | undefined;
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
        const getChipOperationColor = () => {
          switch (operation) {
            case 'create':
              return green[500];
            case 'update':
              return deepPurple[500];
            case 'delete':
              return red[500];
            default:
              return green[500];
          }
        };
        return (
          <Chip
            style={{ fontSize: 12,
              height: 20,
              float: 'left',
              width: 150,
              textTransform: 'uppercase',
              borderRadius: 4,
              backgroundColor: hexToRGB(getChipOperationColor(), 0.08),
              color: getChipOperationColor(),
              border: `1px solid ${getChipOperationColor()}`,
            }}
            label={t_i18n(operation)}
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
      getComputeLink={({ instance_id }: { instance_id: string | undefined }) => {
        return `/dashboard/id/${instance_id}`;
      }}
    />
  );
};

export default DigestNotification;
