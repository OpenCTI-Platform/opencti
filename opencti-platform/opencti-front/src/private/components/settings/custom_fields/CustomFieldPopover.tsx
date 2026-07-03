import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PopoverProps } from '@mui/material/Popover';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import CustomFieldEdition from './CustomFieldEdition';
import { deleteNode } from '../../../../utils/store';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { CustomFieldsLinesPaginationQuery$variables } from './__generated__/CustomFieldsLinesPaginationQuery.graphql';
import { CustomFieldsLine_node$data } from './__generated__/CustomFieldsLine_node.graphql';
import { CustomFieldPopoverEditionQuery$data } from './__generated__/CustomFieldPopoverEditionQuery.graphql';

const customFieldPopoverDeletionMutation = graphql`
  mutation CustomFieldPopoverDeletionMutation($id: ID!) {
    customFieldDefinitionDelete(id: $id)
  }
`;

const customFieldEditionQuery = graphql`
  query CustomFieldPopoverEditionQuery($id: String!) {
    customFieldDefinition(id: $id) {
      ...CustomFieldEdition_customFieldDefinition
    }
  }
`;

interface CustomFieldPopoverProps {
  data: CustomFieldsLine_node$data;
  paginationOptions?: CustomFieldsLinesPaginationQuery$variables;
}

const CustomFieldPopover: FunctionComponent<CustomFieldPopoverProps> = ({
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
      mutation: customFieldPopoverDeletionMutation,
      variables: {
        id: data.id,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_customFieldDefinitions',
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
        title={t_i18n('Update a custom field')}
      >
        <QueryRenderer
          query={customFieldEditionQuery}
          variables={{ id: data.id }}
          render={({
            props,
          }: {
            props: CustomFieldPopoverEditionQuery$data;
          }) => {
            if (props && props.customFieldDefinition) {
              return (
                <CustomFieldEdition
                  customFieldDefinition={props.customFieldDefinition}
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
        message={t_i18n('Do you want to delete this custom field?')}
        warning={{
          title: t_i18n('This is a highly destructive action'),
          message: t_i18n('Deleting this custom field will remove its value from all entities currently using it.'),
        }}
      />
    </>
  );
};

export default CustomFieldPopover;
