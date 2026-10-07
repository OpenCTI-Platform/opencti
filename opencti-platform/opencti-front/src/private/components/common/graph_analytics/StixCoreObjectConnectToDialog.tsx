import React from 'react';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import StixPathFinder from './StixPathFinder';
import useGraphAnalyticsInvestigation from './useGraphAnalyticsInvestigation';
import { collectPathElementIds } from './graphAnalyticsUtils';

interface StixCoreObjectConnectToDialogProps {
  open: boolean;
  onClose: () => void;
  stixCoreObjectId: string;
  stixCoreObjectName: string;
}

/** "Connect to..." action of the entity more-actions menu: find how this entity is connected to another one. */
const StixCoreObjectConnectToDialog = ({ open, onClose, stixCoreObjectId, stixCoreObjectName }: StixCoreObjectConnectToDialogProps) => {
  const { t_i18n } = useFormatter();
  const canInvestigate = useGranted([INVESTIGATION_INUPDATE]);
  const { startInvestigation, inFlight } = useGraphAnalyticsInvestigation();
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="large"
      title={t_i18n('Connect to...')}
      showCloseButton
    >
      {open && (
        <StixPathFinder
          fromId={stixCoreObjectId}
          fromLabel={stixCoreObjectName}
          renderActions={(_, selectedPaths) => canInvestigate && (
            <Button
              disabled={selectedPaths.length === 0 || inFlight}
              onClick={() => startInvestigation(
                t_i18n('Paths from {name}', { values: { name: stixCoreObjectName } }),
                collectPathElementIds(selectedPaths),
                'path_investigation',
              )}
            >
              {t_i18n('Start an investigation with the selected paths')}
            </Button>
          )}
        />
      )}
    </Dialog>
  );
};

export default StixCoreObjectConnectToDialog;
