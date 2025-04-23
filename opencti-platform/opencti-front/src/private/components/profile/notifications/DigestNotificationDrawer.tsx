import React, { FunctionComponent } from 'react';
import DigestNotification from '@components/profile/notifications/DigestNotification';
import Drawer from '@components/common/drawer/Drawer';
import { NotificationsLine_node$data } from '@components/profile/__generated__/NotificationsLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';

interface DigestNotificationDrawerProps {
  notification: NotificationsLine_node$data | undefined;
  open: boolean;
  onClose: () => void;
}

const DigestNotificationDrawer: FunctionComponent<DigestNotificationDrawerProps> = ({ notification, open, onClose }) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer
      title={t_i18n('Digests Details')}
      open={open}
      onClose={onClose}
    >
      <DigestNotification notification={notification} />
    </Drawer>
  );
};

export default DigestNotificationDrawer;
