import React, { useState } from 'react';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Box } from '@mui/material';
import { RouteOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import StixPathFinder from './StixPathFinder';
import useGraphAnalyticsInvestigation from './useGraphAnalyticsInvestigation';
import { collectPathElementIds } from './graphAnalyticsUtils';

interface StixCoreObjectPathFinderButtonProps {
  stixCoreObjectId: string;
  stixCoreObjectName: string;
}

/** "Connect to..." action of the entity header: find how this entity is connected to another one. */
const StixCoreObjectPathFinderButton = ({ stixCoreObjectId, stixCoreObjectName }: StixCoreObjectPathFinderButtonProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const canInvestigate = useGranted([INVESTIGATION_INUPDATE]);
  const { startInvestigation, inFlight } = useGraphAnalyticsInvestigation();
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <IconButton
            aria-label={t_i18n('Connect to...')}
            priority="secondary"
            icon={<RouteOutlined fontSize="small" />}
            onClick={() => setOpen(true)}
            data-testid="graph-connect-to-button"
          />
        </TooltipTrigger>
        <TooltipContent>{t_i18n('Connect to...')}</TooltipContent>
      </Tooltip>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        size="large"
        title={t_i18n('Connect to...')}
        showCloseButton
      >
        <StixPathFinder
          fromId={stixCoreObjectId}
          fromLabel={stixCoreObjectName}
          renderActions={(_, selectedPaths) => canInvestigate && (
            <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                disabled={selectedPaths.length === 0 || inFlight}
                onClick={() => startInvestigation(
                  `${t_i18n('Paths from')} ${stixCoreObjectName}`,
                  collectPathElementIds(selectedPaths),
                  'path_investigation',
                )}
              >
                {t_i18n('Start an investigation with the selected paths')}
              </Button>
            </Box>
          )}
        />
      </Dialog>
    </>
  );
};

export default StixCoreObjectPathFinderButton;
