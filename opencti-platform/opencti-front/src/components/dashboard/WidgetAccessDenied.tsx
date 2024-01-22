import React from 'react';
import { useFormatter } from '../i18n';
import useEnterpriseEdition from '../../utils/hooks/useEnterpriseEdition';

const WidgetAccessDenied = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <span style={{ textAlign: 'center' }}>
        {!isEnterpriseEdition
          ? t_i18n('This feature is only available in OpenCTI Enterprise Edition.')
          : t_i18n('You are not authorized to see this data.')}
      </span>
    </div>
  );
};

export default WidgetAccessDenied;
