import React from 'react';
import { useParams } from 'react-router-dom';
import { useInvestigationState } from '../utils/useInvestigationState';
import { useFormatter } from '../../../../../components/i18n';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@components';

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
        <Button onClick={closeDialog}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleSubmit} color="secondary">{t_i18n('Validate')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default InvestigationRollBackExpandDialog;
