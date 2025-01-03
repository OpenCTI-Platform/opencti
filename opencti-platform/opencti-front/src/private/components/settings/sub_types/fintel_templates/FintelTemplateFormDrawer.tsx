import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { useTheme } from '@mui/styles';
import useFintelTemplateAdd from '@components/settings/sub_types/fintel_templates/useFintelTemplateAdd';
import useFintelTemplateDelete from '@components/settings/sub_types/fintel_templates/useFintelTemplateDelete';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import FintelTemplateForm, { FintelTemplateFormInputKeys, FintelTemplateFormInputs } from './FintelTemplateForm';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import Transition from '../../../../../components/Transition';
import type { Theme } from '../../../../../components/Theme';

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

  const [commitAddMutation] = useFintelTemplateAdd(entitySettingId);
  const [commitEditMutation] = useFintelTemplateEdit();
  const [commitDeleteMutation, deleting] = useFintelTemplateDelete(entitySettingId);

  const {
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
  } = useDeletion({});

  const onDelete = () => {
    if (!template) return;

    commitDeleteMutation(template.id, {
      variables: { id: template.id },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
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
    commitEditMutation({
      variables: { id: template.id, input: [input] },
    });
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
