import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import CityEditionContainer, { cityEditionQuery } from './CityEditionContainer';
import Security from '../../../../utils/Security';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import DeleteDialog from '../../../../components/DeleteDialog';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const CityPopoverDeletionMutation = graphql`
  mutation CityPopoverDeletionMutation($id: ID!) {
    cityEdit(id: $id) {
      delete
    }
  }
`;

const CityPopover = ({ id }: { id: string }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(CityPopoverDeletionMutation);
  const queryRef = useQueryLoading<CityEditionContainerQuery>(
    cityEditionQuery,
    { id },
  );
  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(undefined);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const deletion = useDeletion({ handleClose });

  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/cities');
      },
    });
  };
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  return isFABReplaced
    ? (<></>)
    : (
      <div className={classes.container}>
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this city?')}
        />
        {queryRef && (
          <React.Suspense fallback={<div />}>
            <CityEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
              open={displayEdit}
            />
          </React.Suspense>
        )}
      </div>
    );
};

export default CityPopover;
