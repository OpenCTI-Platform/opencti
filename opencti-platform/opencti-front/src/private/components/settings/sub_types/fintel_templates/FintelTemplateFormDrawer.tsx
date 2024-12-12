import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import { FintelTemplateFormDrawerAddMutation } from './__generated__/FintelTemplateFormDrawerAddMutation.graphql';
import { FintelTemplateFormDrawerEditMutation } from './__generated__/FintelTemplateFormDrawerEditMutation.graphql';
import FintelTemplateForm, { FintelTemplateFormInputKeys, FintelTemplateFormInputs } from './FintelTemplateForm';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';
import { insertNodeFromEdge } from '../../../../../utils/store';

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

const fintelTemplateEditMutation = graphql`
  mutation FintelTemplateFormDrawerEditMutation($id: ID!, $input: [EditInput!]!) {
    fintelTemplateFieldPatch(id: $id, input: $input) {
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

interface FintelTemplateFormDrawerProps {
  isOpen: boolean
  onClose: () => void
  entityType: string
  entitySettingId: string
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

  const [commitAddMutation] = useApiMutation<FintelTemplateFormDrawerAddMutation>(fintelTemplateAddMutation);
  const [commitEditMutation] = useApiMutation<FintelTemplateFormDrawerEditMutation>(fintelTemplateEditMutation);

  const onAdd: FormikConfig<FintelTemplateFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
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
    if (field === 'published') input = { key: 'start_date', value: [value ? new Date() : null] };
    commitEditMutation({
      variables: {
        id: template.id,
        input: [input],
      },
    });
  };

  return (
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
  );
};

export default FintelTemplateFormDrawer;
