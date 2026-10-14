import React, { FunctionComponent, ReactNode, useState } from 'react';
import { FileDownloadOutlined } from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import ConfigPresetExportDrawer from './ConfigPresetExportDrawer';

interface ConfigPresetExportFooterProps {
  // The card's own footer actions, kept above the export button
  children?: ReactNode;
}

// Footer of the Enterprise Edition card when the configuration preset export is available
const ConfigPresetExportFooter: FunctionComponent<ConfigPresetExportFooterProps> = ({ children }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), width: '100%' }}>
      {children && (
        <>
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
            {children}
          </div>
          <Divider />
        </>
      )}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Button variant="secondary" startIcon={<FileDownloadOutlined />} onClick={() => setOpen(true)}>
          {t_i18n('Export Bootstrap Platform Bundle')}
        </Button>
      </div>
      <ConfigPresetExportDrawer open={open} onClose={() => setOpen(false)} />
    </div>
  );
};

export default ConfigPresetExportFooter;
