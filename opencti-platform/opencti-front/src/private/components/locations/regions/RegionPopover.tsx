import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';
import RegionEditionContainer, { regionEditionQuery } from './RegionEditionContainer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const RegionPopoverDeletionMutation = graphql`
  mutation RegionPopoverDeletionMutation($id: ID!) {
    regionEdit(id: $id) {
      delete
    }
  }
`;

const RegionPopover = ({ id }: { id: string }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);

  const [commit] = useApiMutation(RegionPopoverDeletionMutation);
  const queryRef = useQueryLoading<RegionEditionContainerQuery>(
    regionEditionQuery,
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
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/regions');
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
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this region?')}
        />
        {queryRef && (
          <React.Suspense fallback={<div />}>
            <RegionEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
              open={displayEdit}
            />
          </React.Suspense>
        )}
      </div>
    );
};

export default RegionPopover;
