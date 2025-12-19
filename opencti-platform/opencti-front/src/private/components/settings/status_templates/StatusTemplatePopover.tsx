import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PopoverProps } from '@mui/material/Popover';
import Drawer from '@components/common/drawer/Drawer';
import { StatusTemplatesLinesPaginationQuery$variables } from '@components/settings/status_templates/__generated__/StatusTemplatesLinesPaginationQuery.graphql';
import { StatusTemplatesLine_node$data } from '@components/settings/status_templates/__generated__/StatusTemplatesLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StatusTemplateEdition from './StatusTemplateEdition';
import { deleteNode } from '../../../../utils/store';
import { StatusTemplatePopoverEditionQuery$data } from './__generated__/StatusTemplatePopoverEditionQuery.graphql';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const statusTemplatePopoverDeletionMutation = graphql`
  mutation StatusTemplatePopoverDeletionMutation($id: ID!) {
    statusTemplateDelete(id: $id)
  }
`;

const statusTemplateEditionQuery = graphql`
  query StatusTemplatePopoverEditionQuery($id: String!) {
    statusTemplate(id: $id) {
      ...StatusTemplateEdition_statusTemplate
    }
  }
`;

interface StatusTemplatePopoverProps {
  data: StatusTemplatesLine_node$data;
  paginationOptions?: StatusTemplatesLinesPaginationQuery$variables;
}

const StatusTemplatePopover: FunctionComponent<StatusTemplatePopoverProps> = ({
  data,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);

  const handleClose = () => setAnchorEl(null);

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => setDisplayUpdate(false);

  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: statusTemplatePopoverDeletionMutation,
      variables: {
        id: data.id,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_statusTemplates',
        paginationOptions,
        data.id,
      ),
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <>
      <IconButton onClick={handleOpen} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <Drawer
        open={displayUpdate}
        onClose={handleCloseUpdate}
        title={t_i18n('Update a status template')}
      >
        <QueryRenderer
          query={statusTemplateEditionQuery}
          variables={{ id: data.id }}
          render={({
            props,
          }: {
            props: StatusTemplatePopoverEditionQuery$data;
          }) => {
            if (props && props.statusTemplate) {
              return (
                <StatusTemplateEdition
                  statusTemplate={props.statusTemplate}
                  handleClose={handleCloseUpdate}
                />
              );
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </Drawer>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this template?')}
      />
    </>
  );
};

export default StatusTemplatePopover;
