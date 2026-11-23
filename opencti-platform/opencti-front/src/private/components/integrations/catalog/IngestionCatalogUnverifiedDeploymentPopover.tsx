import React, { UIEvent, useEffect, useState } from 'react';
import { useFormatter } from 'src/components/i18n';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, Typography } from '@mui/material';
import Alert from '@mui/material/Alert';
import Button from '@common/button/Button';
import FormControlLabel from '@mui/material/FormControlLabel';
import { Checkbox } from '@filigran/design-system';

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
  const acknowledgeLabel = t_i18n('I acknowledge that this connector is not supported by Filigran and deploy it at my own risk');
  useEffect(() => {
    if (isOpen) {
      setIsAcknowledged(false);
    }
  }, [isOpen]);
  return (
    <Dialog
      open={isOpen}
      onClose={onClose}
      title={t_i18n('Deploy a Community Connector')}
      size="medium"
    >
      <Typography>{t_i18n('This connector has been developed by the community and is not supported by Filigran.')}</Typography>
      <Alert
        severity="info"
        variant="outlined"
        icon={false}
        style={{ marginTop: 20 }}
        // The message slot scrolls (overflow: auto) and would clip the checkbox and its focus ring.
        slotProps={{ message: { sx: { overflow: 'visible' } } }}
      >
        <FormControlLabel
          // MUI's `-11px` offsets its own Checkbox padding, which the library's has not.
          sx={{ margin: 0, gap: 1 }}
          control={(
            <Checkbox
              aria-label={acknowledgeLabel}
              checked={isAcknowledged}
              onCheckedChange={(state) => setIsAcknowledged(state === true)}
            />
          )}
          label={acknowledgeLabel}
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
