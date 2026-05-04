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
import useDeletion from '../../../../../utils/hooks/useDeletion';

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

  const deletion = useDeletion({});

  const handleOpenDelete = (event: UIEvent) => {
    deletion.handleOpenDelete(event);
    setAnchorEl(null);
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
        deletion={deletion}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default CustomViewPopover;
