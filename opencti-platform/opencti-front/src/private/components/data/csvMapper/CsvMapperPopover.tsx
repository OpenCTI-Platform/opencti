import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useQueryLoader } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import CsvMapperEditionContainer, { csvMapperEditionContainerQuery } from '@components/data/csvMapper/CsvMapperEditionContainer';
import { CsvMapperEditionContainerQuery } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerQuery.graphql';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const csvMapperPopoverDelete = graphql`
  mutation CsvMapperPopoverDeleteMutation($id: ID!) {
    csvMapperDelete(id: $id)
  }
`;

interface CsvMapperPopoverProps {
  csvMapperId: string;
  paginationOptions: csvMappers_MappersQuery$variables;
}

const CsvMapperPopover: FunctionComponent<CsvMapperPopoverProps> = ({
  csvMapperId,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);

  // -- Edition --
  const [queryRef, loadQuery] = useQueryLoader<CsvMapperEditionContainerQuery>(csvMapperEditionContainerQuery);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    loadQuery({ id: csvMapperId });
    handleClose();
  };

  // -- Deletion --

  const [commit] = useApiMutation(csvMapperPopoverDelete);

  const deletion = useDeletion({ handleClose });
  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: {
        id: csvMapperId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_csvMappers',
          paginationOptions,
          csvMapperId,
        );
      },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
      },
    });
  };

  return (
    <>
      <IconButton onClick={handleOpen} aria-haspopup="true" size="large" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <CsvMapperEditionContainer
            queryRef={queryRef}
            onClose={() => setDisplayUpdate(false)}
            open={displayUpdate}
          />
        </React.Suspense>
      )}
      <DeleteDialog
        title={t_i18n('Do you want to delete this CSV mapper?')}
        deletion={deletion}
        submitDelete={submitDelete}
      />
    </>
  );
};

export default CsvMapperPopover;
