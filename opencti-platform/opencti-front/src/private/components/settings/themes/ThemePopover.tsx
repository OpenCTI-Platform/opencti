import { MoreVert } from '@mui/icons-material';
import { IconButton, Menu, MenuItem } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import { Disposable } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import ThemeEdition from './ThemeEdition';
import { ThemesLine_data$data } from './__generated__/ThemesLine_data.graphql';
import ThemeDeletion from './ThemeDeletion';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { ThemesLinesSearchQuery$variables } from '../__generated__/ThemesLinesSearchQuery.graphql';

interface ThemePopoverProps {
  theme: ThemesLine_data$data;
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
  version: string;
}

const ThemePopover: FunctionComponent<ThemePopoverProps> = ({
  theme,
  handleRefetch,
  paginationOptions,
  version,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<(EventTarget & Element) | null>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const handleOpen = (event: React.UIEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => { setAnchorEl(null); };
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const handleCloseUpdate = () => setDisplayUpdate(false);
  const deletion = useDeletion({ handleClose });
  const handleExport = () => {
    const { id: _, ...exportTheme } = theme;
    // create file in browser
    const json = JSON.stringify({
      openCTI_version: version,
      type: 'theme',
      configuration: exportTheme,
    }, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const href = URL.createObjectURL(blob);

    // create "a" HTLM element with href to file
    const link = document.createElement('a');
    link.href = href;
    link.download = `${exportTheme.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`;
    document.body.appendChild(link);
    link.click();

    // clean up "a" element & remove ObjectURL
    document.body.removeChild(link);
    URL.revokeObjectURL(href);
  };

  return (
    <div>
      <Security needs={[
        KNOWLEDGE_KNUPDATE,
        KNOWLEDGE_KNGETEXPORT_KNASKEXPORT,
        KNOWLEDGE_KNUPDATE_KNDELETE,
      ]}
      >
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          size="large"
          color="primary"
        >
          <MoreVert />
        </IconButton>
      </Security>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        </Security>
        <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
          <MenuItem onClick={handleExport}>{t_i18n('Export')}</MenuItem>
        </Security>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <ThemeEdition
        theme={theme}
        open={displayUpdate}
        handleClose={handleCloseUpdate}
      />
      <ThemeDeletion
        id={theme.id}
        open={deletion.displayDelete}
        handleClose={deletion.handleCloseDelete}
        handleRefetch={handleRefetch}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default ThemePopover;
