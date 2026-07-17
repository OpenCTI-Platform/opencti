import WidgetContainer from 'src/components/dashboard/WidgetContainer';
import { useFormatter } from 'src/components/i18n';
import { ReactNode } from 'react';
import WidgetNoData from 'src/components/dashboard/WidgetNoData';

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
