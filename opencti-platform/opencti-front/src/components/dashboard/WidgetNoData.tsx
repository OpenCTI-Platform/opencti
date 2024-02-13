import React from 'react';
import { useFormatter } from '../i18n';

const WidgetNoData = () => {
  const { t_i18n } = useFormatter();

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <p>{t_i18n('No entities of this type has been found.')}</p>
    </div>
  );
};

export default WidgetNoData;
