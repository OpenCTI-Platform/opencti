import React from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { useParams } from 'react-router-dom';
import { useInvestigationState } from '../utils/useInvestigationState';
import { useFormatter } from '../../../../../components/i18n';

type InvestigationRollBackExpandDialogProps = {
  closeDialog: () => void;
  handleRollBackToPreExpansionState: () => void;
  isOpen: boolean;
};

const InvestigationRollBackExpandDialog = ({
  closeDialog,
  handleRollBackToPreExpansionState,
  isOpen,
}: InvestigationRollBackExpandDialogProps) => {
  const { workspaceId } = useParams();
  const { t_i18n, fldt } = useFormatter();

  const {
    getLastExpandOp,
  } = useInvestigationState(workspaceId ?? '');

  const handleSubmit = () => {
    handleRollBackToPreExpansionState();
    closeDialog();
  };

  const getLastRollBackExpandDate = () => {
    const expandOp = getLastExpandOp();
    if (expandOp) return fldt(expandOp.dateTime);
    return null;
  };

  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={isOpen}
      onClose={closeDialog}
      fullWidth={true}
      maxWidth="sm"
    >
      <DialogTitle>{t_i18n('Revert to Pre-Expansion State')}</DialogTitle>
      <DialogContent>
        <p>{t_i18n('Last expansion')}: {getLastRollBackExpandDate()}</p>
        <p>{t_i18n('All add or remove actions done on the graph after the last expansion will be lost.')}</p>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={closeDialog}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleSubmit}>{t_i18n('Validate')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default InvestigationRollBackExpandDialog;
