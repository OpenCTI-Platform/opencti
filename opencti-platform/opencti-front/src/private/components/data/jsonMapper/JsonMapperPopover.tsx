import React, { FunctionComponent, UIEvent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useQueryLoader } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import fileDownload from 'js-file-download';
import { jsonMappers_MappersQuery$variables } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { JsonMapperPopoverExportQuery$data } from '@components/data/jsonMapper/__generated__/JsonMapperPopoverExportQuery.graphql';
import JsonMapperEditionContainer, { jsonMapperEditionContainerQuery } from '@components/data/jsonMapper/JsonMapperEditionContainer';
import { JsonMapperEditionContainerQuery } from '@components/data/jsonMapper/__generated__/JsonMapperEditionContainerQuery.graphql';
import JsonMapperCreationContainer from '@components/data/jsonMapper/JsonMapperCreationContainer';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import stopEvent from '../../../../utils/domEvent';
import { fetchQuery } from '../../../../relay/environment';

const jsonMapperPopoverDelete = graphql`
  mutation JsonMapperPopoverDeleteMutation($id: ID!) {
    jsonMapperDelete(id: $id)
  }
`;

const jsonMapperExportQuery = graphql`
  query JsonMapperPopoverExportQuery($id: ID!) {
    jsonMapper(id: $id) {
      name
      toConfigurationExport
    }
  }
`;

interface JsonMapperPopoverProps {
  jsonMapperId: string;
  paginationOptions: jsonMappers_MappersQuery$variables;
}

const JsonMapperPopover: FunctionComponent<JsonMapperPopoverProps> = ({
  jsonMapperId,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);

  // -- Edition --
  const [queryRef, loadQuery] = useQueryLoader<JsonMapperEditionContainerQuery>(jsonMapperEditionContainerQuery);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    loadQuery({ id: jsonMapperId }, { fetchPolicy: 'network-only' });
    handleClose();
  };
  // -- Deletion --
  const [commit] = useApiMutation(jsonMapperPopoverDelete);

  // -- Duplication --
  const [displayDuplicate, setDisplayDuplicate] = useState(false);

  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    loadQuery({ id: jsonMapperId });
    handleClose();
  };

  const deletion = useDeletion({ handleClose });
  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: {
        id: jsonMapperId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_jsonMappers',
          paginationOptions,
          jsonMapperId,
        );
      },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
      },
    });
  };

  const exportJsonMapper = async () => {
    const { jsonMapper } = await fetchQuery(
      jsonMapperExportQuery,
      { id: jsonMapperId },
    ).toPromise() as JsonMapperPopoverExportQuery$data;

    if (jsonMapper) {
      const blob = new Blob([jsonMapper.toConfigurationExport], { type: 'text/json' });
      const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
      const fileName = `${year}${month}${day}_jsonMapper_${jsonMapper.name}.json`;
      fileDownload(blob, fileName);
    }
  };

  const onExport = async (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    await exportJsonMapper();
  };

  return (
    <>
      <IconButton onClick={handleOpen} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDuplicate}>{t_i18n('Duplicate')}</MenuItem>
        <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        <MenuItem onClick={onExport}>{t_i18n('Export')}</MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <JsonMapperEditionContainer
            queryRef={queryRef}
            onClose={() => setDisplayUpdate(false)}
            open={displayUpdate}
          />
          <JsonMapperCreationContainer
            editionQueryRef={queryRef}
            isDuplicated={true}
            paginationOptions={paginationOptions}
            onClose={() => setDisplayDuplicate(false)}
            open={displayDuplicate}
          />
        </React.Suspense>
      )}
      <DeleteDialog
        message={t_i18n('Do you want to delete this JSON mapper?')}
        deletion={deletion}
        submitDelete={submitDelete}
      />
    </>
  );
};

export default JsonMapperPopover;
