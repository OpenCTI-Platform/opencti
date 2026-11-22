import Button from '@common/button/Button';
import { useFormatter } from '../i18n';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';

interface DashboardValuesActionsProps {
  // The name of the preset Reset goes back to (the default one of the user); none: the dashboard defaults.
  resetTargetName?: string;
  disabled?: boolean;
  onReset: () => void;
}

/**
 * Reset of the per user values of a dashboard, variables and time range together. It names what it restores and
 * writes nothing. Whether it shows at all is up to the caller: only when a value differs from its default.
 */
const DashboardValuesActions = ({ resetTargetName, disabled = false, onReset }: DashboardValuesActionsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Button
      className={EXPORT_REMOVE_CLASS}
      variant="tertiary"
      size="small"
      data-testid="dashboard-values-reset"
      disabled={disabled}
      onClick={onReset}
    >
      {resetTargetName !== undefined
        ? t_i18n('Reset to “{name}”', { values: { name: resetTargetName } })
        : t_i18n('Reset to defaults')}
    </Button>
  );
};

export default DashboardValuesActions;
