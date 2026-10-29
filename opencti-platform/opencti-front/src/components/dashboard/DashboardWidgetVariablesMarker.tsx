import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { DataObjectOutlined } from '@mui/icons-material';
import { useFormatter } from '../i18n';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';

interface DashboardWidgetVariablesMarkerProps {
  // Names of the variables the widget filters on.
  names: readonly string[];
}

/**
 * Marks, in the header of a widget, that its data depends on dashboard variables.
 */
const DashboardWidgetVariablesMarker = ({ names }: DashboardWidgetVariablesMarkerProps) => {
  const { t_i18n } = useFormatter();
  if (names.length === 0) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={`noDrag ${EXPORT_REMOVE_CLASS}`}
          data-testid="widget-variables-marker"
          style={{ display: 'inline-flex', verticalAlign: 'middle' }}
        >
          <DataObjectOutlined fontSize="small" color="action" />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <div>{t_i18n('Uses variables:')}</div>
        {names.map((name, index) => <div key={`${name}-${index}`}>{name}</div>)}
      </TooltipContent>
    </Tooltip>
  );
};

export default DashboardWidgetVariablesMarker;
