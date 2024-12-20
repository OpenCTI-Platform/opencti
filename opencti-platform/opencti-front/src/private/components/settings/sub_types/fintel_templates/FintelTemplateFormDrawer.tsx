import Drawer from '@components/common/drawer/Drawer';
import React, { UIEvent } from 'react';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import { FintelTemplateFormDrawerDeleteMutation } from '@components/settings/sub_types/fintel_templates/__generated__/FintelTemplateFormDrawerDeleteMutation.graphql';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { useTheme } from '@mui/styles';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import { FintelTemplateFormDrawerAddMutation } from './__generated__/FintelTemplateFormDrawerAddMutation.graphql';
import FintelTemplateForm, { FintelTemplateFormInputKeys, FintelTemplateFormInputs } from './FintelTemplateForm';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';
import { deleteNodeFromEdge, insertNodeFromEdge } from '../../../../../utils/store';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../../utils/domEvent';
import Transition from '../../../../../components/Transition';
import type { Theme } from '../../../../../components/Theme';

const fintelTemplateAddMutation = graphql`
  mutation FintelTemplateFormDrawerAddMutation($input: FintelTemplateAddInput!) {
    fintelTemplateAdd(input: $input) {
      id
      name
      description
      instance_filters
      settings_types
      start_date
      entity_type
    }
  }
`;

const fintelTemplateFormDrawerDeleteMutation = graphql`
  mutation FintelTemplateFormDrawerDeleteMutation($id: ID!) {
    fintelTemplateDelete(id: $id)
  }
`;

interface FintelTemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  entitySettingId: string
  entityType?: string
  template?: { id: string } & FintelTemplateFormInputs
  onDeleteComplete?: () => void
}

const FintelTemplateFormDrawer = ({
  isOpen,
  onClose,
  entityType,
  entitySettingId,
  template,
  onDeleteComplete,
}: FintelTemplateFormDrawerProps) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  const [commitAddMutation] = useApiMutation<FintelTemplateFormDrawerAddMutation>(fintelTemplateAddMutation);
  const [commitDeleteMutation] = useApiMutation<FintelTemplateFormDrawerDeleteMutation>(fintelTemplateFormDrawerDeleteMutation);
  const [commitEditMutation] = useFintelTemplateEdit();

  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({});

  const onDelete = (e: UIEvent) => {
    if (!template) return;

    stopEvent(e);
    setDeleting(true);
    commitDeleteMutation({
      variables: { id: template.id },
      updater: (store) => {
        deleteNodeFromEdge(
          store,
          'fintelTemplates',
          entitySettingId,
          template.id,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  const onAdd: FormikConfig<FintelTemplateFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    if (!entityType) return;

    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          start_date: values.published ? new Date() : null,
          settings_types: [entityType],
        },
      },
      updater: (store) => {
        insertNodeFromEdge(
          store,
          entitySettingId,
          'fintelTemplates',
          'fintelTemplateAdd',
        );
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        onClose();
        if (response.fintelTemplateAdd) {
          const { id, entity_type } = response.fintelTemplateAdd;
          MESSAGING$.notifySuccess(t_i18n('FINTEL template created'));
          navigate(`${resolveLink(entity_type)}/${entityType}/templates/${id}`);
        }
      },
      onError: (error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

  const onEdit = (field: FintelTemplateFormInputKeys, value: unknown) => {
    if (!template) return;

    let input: { key:string, value: [unknown] } = { key: field, value: [value] };
    if (field === 'published') input = { key: 'start_date', value: [value === 'true' ? new Date() : null] };
    commitEditMutation({ id: template.id, input: [input] });
  };

  return (
    <>
      <Drawer
        title={template ? editionTitle : createTitle}
        open={isOpen}
        onClose={onClose}
      >
        <>
          <FintelTemplateForm
            onClose={onClose}
            onSubmit={onAdd}
            onSubmitField={onEdit}
            isEdition={!!template}
            defaultValues={template}
          />
          {template && (
            <Button
              color="error"
              variant="contained"
              onClick={handleOpenDelete}
              sx={{ marginTop: theme.spacing(2) }}
            >
              {t_i18n('Delete')}
            </Button>
          )}
        </>
      </Drawer>

      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this FINTEL template?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={onDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default FintelTemplateFormDrawer;
