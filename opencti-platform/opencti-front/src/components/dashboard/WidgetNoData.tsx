import React from 'react';
import { useFormatter } from '../i18n';

export const NO_DATA_WIDGET_MESSAGE = 'No data has been found.';

interface WidgetNoDataProps {
  message?: string;
}

const WidgetNoData = ({ message }: WidgetNoDataProps) => {
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
      <p>{message ?? t_i18n(NO_DATA_WIDGET_MESSAGE)}</p>
    </div>
  );
};

export default WidgetNoData;
