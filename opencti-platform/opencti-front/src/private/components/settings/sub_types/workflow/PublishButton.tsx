import { Tooltip, Box, Typography, Divider } from '@mui/material';
import Button from '@common/button/Button';
import CircleIcon from '@mui/icons-material/Circle';
import { useFormatter } from '../../../../../components/i18n';
// import ValidationErrorsTooltip from './ValidationErrorsTooltip';

import { ReactNode } from 'react';

interface WorkflowEntityRef {
  id: string;
  entity_type: string;
}

interface ValidationError {
  type: string;
  message: string;
  path?: WorkflowEntityRef[];
}

interface ValidationErrorsTooltipProps {
  errors: ValidationError[];
  children: ReactNode;
}

const ValidationErrorsTooltip = ({ errors, children }: ValidationErrorsTooltipProps) => {
  const { t_i18n } = useFormatter();

  if (errors.length === 0) {
    return <>{children}</>;
  }

  // Group errors by type
  const groupedErrors = errors.reduce((acc, error) => {
    if (!acc[error.type]) {
      acc[error.type] = [];
    }
    acc[error.type].push(error);
    return acc;
  }, {} as Record<string, ValidationError[]>);

  const tooltipContent = (
    <Box sx={{ maxWidth: 400, p: 1 }}>
      <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 1 }}>
        {t_i18n('Validation Errors')} ({errors.length})
      </Typography>
      <Divider sx={{ mb: 1 }} />
      {Object.entries(groupedErrors).map(([type, typeErrors]) => (
        <Box key={type} sx={{ mb: 1.5 }}>
          <Typography variant="caption" sx={{ fontWeight: 'bold', color: 'error.main', textTransform: 'capitalize' }}>
            {type.replace(/_/g, ' ')}
          </Typography>
          {typeErrors.map((error, index) => (
            <Box key={index} sx={{ ml: 1, mt: 0.5 }}>
              <Typography variant="caption" component="div">
                • {error.message}
              </Typography>
              {error.path && error.path.length > 0 && (
                <Typography variant="caption" component="div" sx={{ ml: 1.5, color: 'text.secondary', fontStyle: 'italic' }}>
                  Affected: {error.path.map((ref) => `${ref.entity_type} (${ref.id})`).join(', ')}
                </Typography>
              )}
            </Box>
          ))}
        </Box>
      ))}
    </Box>
  );

  return (
    <Tooltip title={tooltipContent} placement="bottom-start">
      <span>{children}</span>
    </Tooltip>
  );
};

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
          >
            {t_i18n('Published')}
          </Button>
        </span>
      </Tooltip>
    );
  }

  // Red: Not published and has validation errors
  if (!published && validationErrors.length > 0) {
    return (

      <ValidationErrorsTooltip errors={validationErrors}>
        <span>
          <Button
            startIcon={<CircleIcon color="error" />}
            variant="secondary"
            disabled
          >
            {t_i18n('Cannot Publish')}
          </Button>
        </span>
      </ValidationErrorsTooltip>
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
        >
          {t_i18n('Publish')}
        </Button>
      </span>
    </Tooltip>
  );
};

export default PublishButton;
