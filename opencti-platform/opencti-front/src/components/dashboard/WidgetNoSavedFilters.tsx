import React from 'react';
import { useFormatter } from '../i18n';

const WidgetNoSavedFilters = () => {
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
      <span style={{ textAlign: 'center' }}>
        {t_i18n('The saved filter used by this widget is not available.')}
      </span>
    </div>
  );
};

export default WidgetNoSavedFilters;
