import { Tooltip } from '@mui/material';
import Button from '@common/button/Button';
import CircleIcon from '@mui/icons-material/Circle';
import { useFormatter } from '../../../../../components/i18n';

interface ValidationError {
  type: string;
  message: string;
  path?: Array<{ id: string; entity_type: string }> | null;
}

const BUTTON_WIDTH = 120;

interface ValidationStatus {
  published: boolean;
  validationErrors: ValidationError[];
}

interface PublishButtonProps {
  validationStatus: ValidationStatus | null;
  onPublish: () => void;
  disabled?: boolean;
}

const PublishButton = ({ validationStatus, onPublish, disabled }: PublishButtonProps) => {
  const { t_i18n } = useFormatter();

  if (!validationStatus) {
    return null;
  }

  const { published, validationErrors } = validationStatus;

  // Green: Published and no errors
  if (published && validationErrors.length === 0) {
    return (
      <Tooltip title={t_i18n('Workflow is published')}>
        <span>
          <Button
            startIcon={<CircleIcon color="success" />}
            variant="secondary"
            disabled
            sx={{ width: BUTTON_WIDTH }}
          >
            {t_i18n('Published')}
          </Button>
        </span>
      </Tooltip>
    );
  }

  // Red: Not published but has validation errors — still clickable, will show toast on click
  if (!published && validationErrors.length > 0) {
    return (
      <Tooltip title={t_i18n('Click to see validation errors')}>
        <span>
          <Button
            startIcon={<CircleIcon color="error" />}
            variant="secondary"
            onClick={onPublish}
            disabled={disabled}
            sx={{ width: BUTTON_WIDTH }}
          >
            {t_i18n('Publish')}
          </Button>
        </span>
      </Tooltip>
    );
  }

  // Orange: Not published but can publish (no errors)
  return (
    <Tooltip title={t_i18n('Click to publish this workflow version')}>
      <span>
        <Button
          startIcon={<CircleIcon color="warning" />}
          variant="secondary"
          onClick={onPublish}
          disabled={disabled}
          sx={{ width: BUTTON_WIDTH }}
        >
          {t_i18n('Publish')}
        </Button>
      </span>
    </Tooltip>
  );
};

export default PublishButton;
