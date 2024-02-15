import React from 'react';
import Alert from '@mui/material/Alert';
import useConfidenceLevel from '../utils/hooks/useConfidenceLevel';
import { useFormatter } from './i18n';

type AlertConfidenceForEntityProps = {
  entity: {
    confidence?: number | null
  }
};

const AlertConfidenceForEntity: React.FC<AlertConfidenceForEntityProps> = ({ entity }) => {
  const { t_i18n } = useFormatter();
  const { checkConfidenceForEntity } = useConfidenceLevel();

  if (checkConfidenceForEntity(entity)) {
    return null;
  }

  return (
    <Alert
      severity="warning"
      variant="outlined"
      style={{ marginTop: 20, marginBottom: 20 }}
    >
      {t_i18n('Your maximum confidence level is insufficient to edit this object.')}
    </Alert>
  );
};

export default AlertConfidenceForEntity;
