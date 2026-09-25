import React, { FunctionComponent } from 'react';
import { AlarmOnOutlined, NotificationsOutlined } from '@mui/icons-material';
import { Link, Navigate, useLocation } from 'react-router';
import { Tabs, TabsList, TabsTrigger, Text } from '@filigran/design-system';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import Alerts from './Alerts';
import Triggers from './Triggers';

const alertsTabPath = '/dashboard/profile/notifications';
const triggersTabPath = '/dashboard/profile/notifications/triggers';

const Notifications: FunctionComponent = () => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  const isTriggersTab = location.pathname === triggersTabPath;
  const activeTabPath = isTriggersTab ? triggersTabPath : alertsTabPath;
  const pageTitle = t_i18n('Notification Center');

  if (location.pathname === `${alertsTabPath}/alerts`) {
    return <Navigate to={alertsTabPath} replace={true} />;
  }

  if (location.pathname !== alertsTabPath && !isTriggersTab) {
    return <Navigate to={alertsTabPath} replace={true} />;
  }

  setTitle(pageTitle);

  return (
    <div>
      <Breadcrumbs elements={[
        { label: t_i18n('Notifications'), link: '/dashboard/profile/notifications', current: false },
        { label: isTriggersTab ? t_i18n('Triggers') : t_i18n('Alerts'), current: true },
      ]}
      />
      <Text variant="title-xl" className="mt-6 mb-6">
        {t_i18n('Notification Center')}
      </Text>
      <div style={{ marginTop: 20 }}>
        <Tabs value={activeTabPath} panels="external">
          <TabsList>
            <TabsTrigger value={alertsTabPath} asChild>
              <Link to={alertsTabPath} data-testid="notifications-tab-alerts">
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <NotificationsOutlined fontSize="small" />
                  {t_i18n('Alerts')}
                </span>
              </Link>
            </TabsTrigger>
            <TabsTrigger value={triggersTabPath} asChild>
              <Link to={triggersTabPath} data-testid="notifications-tab-triggers">
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <AlarmOnOutlined fontSize="small" />
                  {t_i18n('Triggers')}
                </span>
              </Link>
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <div style={{ marginTop: 20 }}>
          {isTriggersTab ? <Triggers /> : <Alerts />}
        </div>
      </div>
    </div>
  );
};

export default Notifications;
