import React, { UIEvent, useEffect, useState } from 'react';
import { useFormatter } from 'src/components/i18n';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, Typography } from '@mui/material';
import Alert from '@mui/material/Alert';
import Button from '@common/button/Button';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';

type IngestionCatalogUnverifiedDeploymentPopoverProps = {
  onClose: (e: UIEvent) => void;
  isOpen: boolean;
  onDeploy: () => void;
};

const IngestionCatalogUnverifiedDeploymentPopover: React.FC<IngestionCatalogUnverifiedDeploymentPopoverProps> = ({
  onClose,
  isOpen,
  onDeploy,
}) => {
  const { t_i18n } = useFormatter();
  const [isAcknowledged, setIsAcknowledged] = useState(false);
  useEffect(() => {
    if (isOpen) {
      setIsAcknowledged(false);
    }
  }, [isOpen]);
  return (
    <Dialog
      open={isOpen}
      onClose={onClose}
      title={t_i18n('Deploy unverified connector')}
      size="medium"
    >
      <Typography>{t_i18n('This connector has not been developed and verified by Filigran. As such, Filigran cannot be held liable for any issues that may occur during its use.')}</Typography>
      <Alert
        severity="info"
        variant="outlined"
        icon={false}
        style={{ marginTop: 20 }}
      >
        <FormControlLabel
          control={(
            <Checkbox
              onClick={() => setIsAcknowledged((prev) => !prev)}
              checked={isAcknowledged}
            />
          )}
          label={t_i18n('I understand and accept the risks of deploying an unverified connector')}
        />
      </Alert>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>
          {t_i18n('Back')}
        </Button>
        <Button
          onClick={(e) => {
            onClose(e);
            onDeploy();
          }}
          disabled={!isAcknowledged}
        >
          {t_i18n('Deploy')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default IngestionCatalogUnverifiedDeploymentPopover;
