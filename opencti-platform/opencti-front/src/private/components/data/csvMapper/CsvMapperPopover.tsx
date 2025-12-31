import React, { FunctionComponent, UIEvent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useQueryLoader } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import CsvMapperEditionContainer, { csvMapperEditionContainerQuery } from '@components/data/csvMapper/CsvMapperEditionContainer';
import { CsvMapperEditionContainerQuery } from '@components/data/csvMapper/__generated__/CsvMapperEditionContainerQuery.graphql';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import CsvMapperCreationContainer from '@components/data/csvMapper/CsvMapperCreationContainer';
import fileDownload from 'js-file-download';
import { CsvMapperPopoverExportQuery$data } from '@components/data/csvMapper/__generated__/CsvMapperPopoverExportQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import stopEvent from '../../../../utils/domEvent';
import { fetchQuery } from '../../../../relay/environment';

const csvMapperPopoverDelete = graphql`
  mutation CsvMapperPopoverDeleteMutation($id: ID!) {
    csvMapperDelete(id: $id)
  }
`;

const csvMapperExportQuery = graphql`
  query CsvMapperPopoverExportQuery($id: ID!) {
    csvMapper(id: $id) {
      name
      toConfigurationExport
    }
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
    loadQuery({ id: csvMapperId }, { fetchPolicy: 'network-only' });
    handleClose();
  };

  // -- Duplication --
  const [displayDuplicate, setDisplayDuplicate] = useState(false);

  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    loadQuery({ id: csvMapperId });
    handleClose();
  };

  // -- Deletion --

  const [commit] = useApiMutation(csvMapperPopoverDelete);

  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
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
        setDeleting(false);
        handleClose();
      },
    });
  };

  const exportCsvMapper = async () => {
    const { csvMapper } = await fetchQuery(
      csvMapperExportQuery,
      { id: csvMapperId },
    ).toPromise() as CsvMapperPopoverExportQuery$data;

    if (csvMapper) {
      const blob = new Blob([csvMapper.toConfigurationExport], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_csvMapper_${csvMapper.name}.json`;
      fileDownload(blob, fileName);
    }
  };

  const onExport = async (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    await exportCsvMapper();
  };

  return (
    <>
      <IconButton onClick={handleOpen} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDuplicate}>{t_i18n('Duplicate')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        <MenuItem onClick={onExport}>{t_i18n('Export')}</MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <CsvMapperEditionContainer
            queryRef={queryRef}
            onClose={() => setDisplayUpdate(false)}
            open={displayUpdate}
          />
          <CsvMapperCreationContainer
            editionQueryRef={queryRef}
            isDuplicated={true}
            paginationOptions={paginationOptions}
            onClose={() => setDisplayDuplicate(false)}
            open={displayDuplicate}
          />
        </React.Suspense>
      )}
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this CSV mapper?')}
      />
    </>
  );
};

export default CsvMapperPopover;
