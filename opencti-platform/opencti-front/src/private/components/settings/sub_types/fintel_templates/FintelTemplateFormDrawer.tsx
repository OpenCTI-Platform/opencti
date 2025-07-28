import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import useFintelTemplateAdd from '@components/settings/sub_types/fintel_templates/useFintelTemplateAdd';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import FintelTemplateForm, { FintelTemplateFormInputKeys, FintelTemplateFormInputs } from './FintelTemplateForm';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';

interface FintelTemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  entitySettingId: string
  entityType?: string
  template?: { id: string } & FintelTemplateFormInputs
}

const FintelTemplateFormDrawer = ({
  isOpen,
  onClose,
  entityType,
  entitySettingId,
  template,
}: FintelTemplateFormDrawerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  const [commitAddMutation] = useFintelTemplateAdd(entitySettingId);
  const [commitEditMutation] = useFintelTemplateEdit();

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
        <FintelTemplateForm
          onClose={onClose}
          onSubmit={onAdd}
          onSubmitField={onEdit}
          isEdition={!!template}
          defaultValues={template}
        />
      </Drawer>
    </>
  );
};

export default FintelTemplateFormDrawer;
