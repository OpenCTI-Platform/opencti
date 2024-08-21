import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import { useFormatter } from '../../../../components/i18n';
import { positionEditionQuery } from './PositionEdition';
import PositionEditionContainer from './PositionEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { QueryRenderer } from '../../../../relay/environment';
import PositionPopoverDeletion from './PositionPopoverDeletion';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const PositionPopover = ({ id }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);

  return isFABReplaced
    ? (<></>)
    : (
      <>
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleClose}
        >
          <MenuItem onClick={handleOpenEdit}>
            {t_i18n('Update')}
          </MenuItem>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>
              {t_i18n('Delete')}
            </MenuItem>
          </Security>
        </Menu>
        <PositionPopoverDeletion
          positionId={id}
          displayDelete={displayDelete}
          handleClose={handleClose}
          handleCloseDelete={handleCloseDelete}
        />
        <QueryRenderer
          query={positionEditionQuery}
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              return (
                <PositionEditionContainer
                  position={props.position}
                  handleClose={handleCloseEdit}
                  open={displayEdit}
                />
              );
            }
            return <div />;
          }}
        />
      </>
    );
};
export default PositionPopover;
