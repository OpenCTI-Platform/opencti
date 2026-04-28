import { UIEvent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import stopEvent from '../../../../../utils/domEvent';
import { CustomViewPopover_customView$key } from './__generated__/CustomViewPopover_customView.graphql';
import CustomViewDeletionDialog from './CustomViewDeletionDialog';

const customViewPopoverFragment = graphql`
  fragment CustomViewPopover_customView on CustomView {
    id
  }
`;

interface CustomViewPopoverProps {
  data: CustomViewPopover_customView$key;
  paginationOptions: Record<string, unknown>;
}

const CustomViewPopover = ({ data, paginationOptions }: CustomViewPopoverProps) => {
  const { t_i18n } = useFormatter();
  const customView = useFragment(customViewPopoverFragment, data);
  const { id } = customView;

  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const handleOpen = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const [isDeletionDialogOpen, setIsDeletionDialogOpen] = useState(false);
  const handleOpenDelete = (event: UIEvent) => {
    stopEvent(event);
    setIsDeletionDialogOpen(true);
    setAnchorEl(null);
  };
  const handleCloseDelete = (event?: UIEvent) => {
    if (event) {
      stopEvent(event);
    }
    setIsDeletionDialogOpen(false);
  };

  return (
    <div>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="small"
        color="primary"
        aria-label={t_i18n('Custom view popover of actions')}
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose} aria-label="Custom view menu">
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <CustomViewDeletionDialog
        id={id}
        isOpen={isDeletionDialogOpen}
        handleClose={handleCloseDelete}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default CustomViewPopover;
