import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import { FileExportOutline } from 'mdi-material-ui';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreObjectFileExportButtonProps {
  onOpen: () => void
  isExportPossible: boolean
}

const StixCoreObjectFileExportButton = ({
  onOpen,
  isExportPossible,
}: StixCoreObjectFileExportButtonProps) => {
  const { t_i18n } = useFormatter();
  const title = isExportPossible
    ? t_i18n('Generate an export')
    : t_i18n('No export connector available to generate an export');

  return (
    <Tooltip aria-label="generate-export" title={title}>
      <ToggleButton
        onClick={onOpen}
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
          color={isExportPossible ? 'primary' : 'disabled'}
        />
      </ToggleButton>
    </Tooltip>
  );
};

export default StixCoreObjectFileExportButton;
