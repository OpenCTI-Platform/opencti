import React, { FunctionComponent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useMutation } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import {
  CsvMapperLinesPaginationQuery$variables,
} from '@components/data/csvMapper/__generated__/CsvMapperLinesPaginationQuery.graphql';
import CsvMapperEditionContainer, {
  csvMapperEditionContainerQuery,
} from '@components/data/csvMapper/CsvMapperEditionContainer';
import {
  CsvMapperEditionContainerQuery,
} from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const csvMapperPopoverDelete = graphql`
  mutation CsvMapperPopoverDeleteMutation($id: ID!) {
    csvMapperDelete(id: $id)
  }
`;

interface CsvMapperPopoverProps {
  csvMapperId: string;
  paginationOptions: CsvMapperLinesPaginationQuery$variables;
}

const CsvMapperPopover: FunctionComponent<CsvMapperPopoverProps> = ({
  csvMapperId,
  paginationOptions,
}) => {
  const { t } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);

  // -- Edition --
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const queryRef = useQueryLoading<CsvMapperEditionContainerQuery>(
    csvMapperEditionContainerQuery,
    { id: csvMapperId },
  );

  // -- Deletion --

  const [commit] = useMutation(csvMapperPopoverDelete);

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
      <IconButton onClick={handleOpen} aria-haspopup="true" size="large">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t('Update')}</MenuItem>
        <MenuItem onClick={deletion.handleOpenDelete}>{t('Delete')}</MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <CsvMapperEditionContainer queryRef={queryRef}
                                     onClose={() => setDisplayUpdate(false)}
                                     open={displayUpdate} />
        </React.Suspense>
      )}
      <DeleteDialog title={t('Do you want to delete this csv mapper ?')}
                    deletion={deletion}
                    submitDelete={submitDelete} />
    </>
  );
};

export default CsvMapperPopover;
