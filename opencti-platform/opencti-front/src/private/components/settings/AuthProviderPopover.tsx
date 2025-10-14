import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import React from 'react';
import AuthProviderForm, { AuthProvider } from '@components/settings/AuthProviderForm';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import useDeletion from '../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../components/DeleteDialog';

const AuthProviderPopover = ({ provider, onDelete, onUpdate }: { provider: AuthProvider, onDelete: (p: AuthProvider) => void, onUpdate: (p: AuthProvider) => void }) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const [openUpdate, setOpenUdate] = React.useState<boolean>(false);

  const handleOpen = (e: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(e.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleOpenUpdate = () => {
    setOpenUdate(true);
    setAnchorEl(null);
  };

  const deletion = useDeletion({ handleClose });
  const { displayDelete, handleOpenDelete, handleCloseDelete } = deletion;

  return (
    <div style={{ margin: 0 }}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        color="primary"
        disabled={!provider.dynamic}
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={!!anchorEl && !openUpdate && !displayDelete}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        isOpen={displayDelete}
        message={t_i18n('Do you want to delete this saved filter?')}
        submitDelete={() => {
          onDelete(provider);
          handleCloseDelete();
        }}
        onClose={handleCloseDelete}
      />
      {openUpdate && (
        <Drawer
          open={openUpdate}
          onClose={() => setOpenUdate(false)}
          title={t_i18n('Update provider')}
        >
          <AuthProviderForm onClose={handleClose} provider={provider} onUpdate={onUpdate} />
        </Drawer>
      )}
    </div>
  );
};

export default AuthProviderPopover;
