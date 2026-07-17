import { ReactNode } from 'react';
import WidgetContainer from './WidgetContainer';
import WidgetNoData from './WidgetNoData';
import { useFormatter } from '../i18n';

interface WidgetNotImplementedProps {
  popover: ReactNode;
}

const WidgetNotImplemented = ({ popover }: WidgetNotImplementedProps) => {
  const { t_i18n } = useFormatter();
  return (
    <WidgetContainer action={popover}>
      <WidgetNoData message={t_i18n('Not implemented yet')} />
    </WidgetContainer>
  );
};

export default WidgetNotImplemented;
