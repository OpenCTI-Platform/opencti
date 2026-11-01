import Button from '@common/button/Button';
import { useFormatter } from '../i18n';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';

interface DashboardValuesActionsProps {
  // Allows setting the current values (variables and time range) as the dashboard defaults.
  canSetAsDefaults: boolean;
  disabled?: boolean;
  onReset: () => void;
  onSetAsDefaults?: () => void;
}

/**
 * The actions on the per user values of a dashboard, variables and time range together.
 * Whether they show at all is up to the caller: only when a value differs from its default.
 */
const DashboardValuesActions = ({ canSetAsDefaults, disabled = false, onReset, onSetAsDefaults }: DashboardValuesActionsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      <Button
        className={EXPORT_REMOVE_CLASS}
        variant="tertiary"
        size="small"
        disabled={disabled}
        onClick={onReset}
      >
        {t_i18n('Reset')}
      </Button>
      {canSetAsDefaults && (
        <Button
          className={EXPORT_REMOVE_CLASS}
          variant="secondary"
          size="small"
          disabled={disabled}
          onClick={onSetAsDefaults}
        >
          {t_i18n('Set as default values')}
        </Button>
      )}
    </>
  );
};

export default DashboardValuesActions;
