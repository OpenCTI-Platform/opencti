import Button from '@common/button/Button';
import { ButtonProps, Tooltip } from '@mui/material';
import { useFormatter } from '../../i18n';

interface BulkTextModalButtonProps {
  onClick: ButtonProps['onClick'];
  disabled?: ButtonProps['disabled'];
  title?: string;
}

const BulkTextModalButton = ({ onClick, title, disabled }: BulkTextModalButtonProps) => {
  const { t_i18n } = useFormatter();

  const bulkButton = (
    <Button
      variant="secondary"
      onClick={onClick}
      disabled={disabled}

    >
      {title || t_i18n('Create multiple entities')}
    </Button>
  );

  return disabled
    ? <Tooltip title={t_i18n('Bulk creation not supported for this type')}>{bulkButton}</Tooltip>
    : bulkButton;
};

export default BulkTextModalButton;
