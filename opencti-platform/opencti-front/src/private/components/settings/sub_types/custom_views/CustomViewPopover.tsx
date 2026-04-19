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
import useCustomViewEdit from './useCustomViewEdit';

const customViewPopoverFragment = graphql`
  fragment CustomViewPopover_customView on CustomView {
    id
    enabled
  }
`;

interface CustomViewPopoverProps {
  data: CustomViewPopover_customView$key;
  paginationOptions: Record<string, unknown>;
}

const CustomViewPopover = ({ data, paginationOptions }: CustomViewPopoverProps) => {
  const { t_i18n } = useFormatter();
  const customView = useFragment(customViewPopoverFragment, data);

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

  const [commitCustomViewMutation] = useCustomViewEdit();
  const handleToggleEnabled = (event: UIEvent) => {
    stopEvent(event);
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{
          key: 'enabled',
          value: [!customView.enabled],
        }],
      },
    });
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
        <MenuItem onClick={handleToggleEnabled}>{customView.enabled ? t_i18n('Disable') : t_i18n('Enable')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <CustomViewDeletionDialog
        id={customView.id}
        deletion={deletion}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default CustomViewPopover;
