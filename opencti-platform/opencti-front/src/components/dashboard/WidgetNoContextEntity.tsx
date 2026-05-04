import { useFormatter } from '../i18n';
import type { WidgetContext } from '../../utils/widget/widget';
import WidgetNoData from './WidgetNoData';

interface WidgetNoContextEntityProps {
  context?: WidgetContext;
}

const WidgetNoContextEntity = ({
  context,
}: WidgetNoContextEntityProps) => {
  const { t_i18n } = useFormatter();
  return context?.kind === 'custom-view' && context.missingContextEntityFiller
    ? context.missingContextEntityFiller
    : <WidgetNoData message={t_i18n('This widget requires a context entity to be displayed.')} />;
};

export default WidgetNoContextEntity;
