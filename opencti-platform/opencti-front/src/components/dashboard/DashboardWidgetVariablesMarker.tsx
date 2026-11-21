import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Variable } from 'mdi-material-ui';
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
        {/* A button, named after the variables, so that the tooltip also opens from the keyboard. It does nothing on click. */}
        <button
          type="button"
          className={`noDrag ${EXPORT_REMOVE_CLASS}`}
          data-testid="widget-variables-marker"
          aria-label={`${t_i18n('Uses variables:')} ${names.join(', ')}`}
          style={{ display: 'inline-flex', padding: 0, border: 0, background: 'none', cursor: 'default' }}
        >
          {/* The glyph of the Variable value source in the widget filters. */}
          <Variable fontSize="small" color="action" aria-hidden />
        </button>
      </TooltipTrigger>
      <TooltipContent>
        <div>{t_i18n('Uses variables:')}</div>
        {names.map((name, index) => <div key={`${name}-${index}`}>{name}</div>)}
      </TooltipContent>
    </Tooltip>
  );
};

export default DashboardWidgetVariablesMarker;
