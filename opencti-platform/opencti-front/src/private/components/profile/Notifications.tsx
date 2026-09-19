import React, { FunctionComponent } from 'react';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import Alerts from './Alerts';

const Notifications: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  setTitle(t_i18n('Alerts'));

  return (
    <div>
      <Breadcrumbs elements={[{ label: t_i18n('Alerts'), current: true }]} />
      <div style={{ marginTop: 20 }}>
        <Alerts />
      </div>
    </div>
  );
};

export default Notifications;
