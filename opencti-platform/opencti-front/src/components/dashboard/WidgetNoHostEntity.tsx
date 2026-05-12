import { useFormatter } from '../i18n';
import type { WidgetHost } from '../../utils/widget/widget';
import WidgetNoData from './WidgetNoData';

interface WidgetNoHostEntityProps {
  host?: WidgetHost;
}

const WidgetNoHostEntity = ({
  host,
}: WidgetNoHostEntityProps) => {
  const { t_i18n } = useFormatter();
  return host?.kind === 'custom-view' && host.missingHostEntityFiller
    ? host.missingHostEntityFiller
    : <WidgetNoData message={t_i18n('This widget requires a context entity to be displayed.')} />;
};

export default WidgetNoHostEntity;
