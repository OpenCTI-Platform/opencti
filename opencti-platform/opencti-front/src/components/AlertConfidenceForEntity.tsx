import React from 'react';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/styles';
import useConfidenceLevel from '../utils/hooks/useConfidenceLevel';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';

type AlertConfidenceForEntityProps = {
  entity: {
    entity_type?: string | null
    confidence?: number | null
  }
};

const AlertConfidenceForEntity: React.FC<AlertConfidenceForEntityProps> = ({ entity }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { checkConfidenceForEntity } = useConfidenceLevel();

  if (checkConfidenceForEntity(entity)) {
    return null;
  }

  return (
    <Alert
      severity="warning"
      variant="outlined"
      style={{ marginBottom: theme.spacing(2) }}
    >
      {t_i18n('Your confidence level is insufficient to edit this object.')}
    </Alert>
  );
};

export default AlertConfidenceForEntity;
