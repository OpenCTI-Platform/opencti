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
import { ThemesLinesSearchQuery$variables } from './__generated__/ThemesLinesSearchQuery.graphql';
import ThemeType, { deserializeThemeManifest } from './ThemeType';
import handleExportJson from './ThemeExportHandler';

interface ThemePopoverProps {
  themeData: ThemesLine_data$data;
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
}

const ThemePopover: FunctionComponent<ThemePopoverProps> = ({
  themeData,
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<(EventTarget & Element) | null>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const theme: ThemeType = {
    id: themeData.id,
    name: themeData.name,
    ...deserializeThemeManifest(themeData.manifest),
  };

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
    handleExportJson(theme);
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
          data-testid={`${theme.name}-popover`}
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
          <MenuItem
            onClick={handleOpenUpdate}
            aria-label={t_i18n('Update')}
          >
            {t_i18n('Update')}
          </MenuItem>
        </Security>
        <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
          <MenuItem
            onClick={handleExport}
            aria-label={t_i18n('Export')}
          >
            {t_i18n('Export')}
          </MenuItem>
        </Security>
        {!theme.system_default && (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem
              onClick={deletion.handleOpenDelete}
              aria-label={t_i18n('Delete')}
            >
              {t_i18n('Delete')}
            </MenuItem>
          </Security>
        )}
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
