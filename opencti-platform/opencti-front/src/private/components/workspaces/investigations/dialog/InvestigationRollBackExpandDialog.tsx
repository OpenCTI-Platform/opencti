import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import { useParams } from 'react-router-dom';
import { useFormatter } from '../../../../../components/i18n';
import { useInvestigationState } from '../utils/useInvestigationState';

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
      open={isOpen}
      onClose={closeDialog}
      title={t_i18n('Revert to Pre-Expansion State')}
    >
      <p>{t_i18n('Last expansion')}: {getLastRollBackExpandDate()}</p>
      <p>{t_i18n('All add or remove actions done on the graph after the last expansion will be lost.')}</p>
      <DialogActions>
        <Button variant="secondary" onClick={closeDialog}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleSubmit}>{t_i18n('Validate')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default InvestigationRollBackExpandDialog;
