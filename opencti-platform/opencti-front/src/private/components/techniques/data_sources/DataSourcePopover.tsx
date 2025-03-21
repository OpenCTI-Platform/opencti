import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataSourceEditionContainerQuery } from './__generated__/DataSourceEditionContainerQuery.graphql';
import DataSourceEditionContainer, { dataSourceEditionQuery } from './DataSourceEditionContainer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const DataSourcePopoverDeletionMutation = graphql`
  mutation DataSourcePopoverDeletionMutation($id: ID!) {
    dataSourceDelete(id: $id)
  }
`;

const DataSourcePopover = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [commit] = useApiMutation(DataSourcePopoverDeletionMutation);
  const queryRef = useQueryLoading<DataSourceEditionContainerQuery>(
    dataSourceEditionQuery,
    { id },
  );

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => setAnchorEl(null);

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
        navigate('/dashboard/techniques/data_sources');
      },
    });
  };

  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };

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
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this data source?')}
        />
        {queryRef && (
          <React.Suspense fallback={<div />}>
            <DataSourceEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
              open={displayEdit}
            />
          </React.Suspense>
        )}
      </>
    );
};

export default DataSourcePopover;
