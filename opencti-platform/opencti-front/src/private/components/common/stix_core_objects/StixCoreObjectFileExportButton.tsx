import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { FileExportOutline } from 'mdi-material-ui';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';

interface StixCoreObjectFileExportButtonProps {
  onOpen: () => void
  isExportPossible: boolean
}

const StixCoreObjectFileExportButton = ({
  onOpen,
  isExportPossible,
}: StixCoreObjectFileExportButtonProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const disabledInDraft = !!me.draftContext;
  let title = t_i18n('No export connector available to generate an export');
  if (disabledInDraft) {
    title = t_i18n('Not available in draft');
  } else if (isExportPossible) {
    title = t_i18n('Generate an export');
  }

  return (
    <Tooltip aria-label="generate-export" title={title}>
      <ToggleButton
        onClick={() => !disabledInDraft && onOpen()}
        disabled={!isExportPossible}
        value="quick-export"
        aria-label="Quick export"
        aria-haspopup="true"
        color="primary"
        size="small"
        style={{ marginRight: 3 }}
      >
        <FileExportOutline
          fontSize="small"
          color={!disabledInDraft && isExportPossible ? 'primary' : 'disabled'}
        />
      </ToggleButton>
    </Tooltip>
  );
};

export default StixCoreObjectFileExportButton;
