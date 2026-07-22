import Drawer from '@components/common/drawer/Drawer';
import { useState } from 'react';
import { type FormikConfig } from 'formik';
import { useNavigate } from 'react-router-dom';
import useFintelTemplateAdd from './useFintelTemplateAdd';
import useFintelTemplateEdit from './useFintelTemplateEdit';
import FintelTemplateForm, { FintelTemplateFormInputKeys, FintelTemplateFormInputs } from './FintelTemplateForm';
import FintelTemplateReplaceDefaultDialog from './FintelTemplateReplaceDefaultDialog';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';

type PendingDefaultCreate = { kind: 'create'; values: FintelTemplateFormInputs };
type PendingDefaultEdit = { kind: 'edit'; revert: () => void };
type PendingDefault = PendingDefaultCreate | PendingDefaultEdit;

interface FintelTemplateFormDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  entitySettingId: string;
  entityType?: string;
  template?: { id: string } & FintelTemplateFormInputs;
  currentDefaultName?: string;
}

const FintelTemplateFormDrawer = ({
  isOpen,
  onClose,
  entityType,
  entitySettingId,
  template,
  currentDefaultName,
}: FintelTemplateFormDrawerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create a template');
  const editionTitle = t_i18n('Update a template');

  const [commitAddMutation] = useFintelTemplateAdd(entitySettingId);
  const [commitEditMutation] = useFintelTemplateEdit();
  const [pendingDefault, setPendingDefault] = useState<PendingDefault | null>(null);

  const handleSetDefault = (revert: () => void) => {
    if (currentDefaultName) {
      setPendingDefault({ kind: 'edit', revert });
    } else {
      commitEditMutation({
        variables: { id: template!.id, input: [{ key: 'default', value: ['true'] }] },
        onError: (err) => {
          handleError(err);
          revert();
        },
      });
    }
  };

  const handleUnsetDefault = (revert: () => void) => {
    commitEditMutation({
      variables: { id: template!.id, input: [{ key: 'default', value: ['false'] }] },
      onError: (err) => {
        handleError(err);
        revert();
      },
    });
  };

  const handleDefaultToggle = (value: boolean, revert: () => void) => {
    if (value) handleSetDefault(revert);
    else handleUnsetDefault(revert);
  };

  const doAdd = (values: FintelTemplateFormInputs, setSubmitting?: (isSubmitting: boolean) => void) => {
    if (!entityType) return;

    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          start_date: values.published ? new Date() : null,
          settings_types: [entityType],
          default: values.default,
        },
      },
      onCompleted: (response) => {
        setSubmitting?.(false);
        onClose();
        if (response.fintelTemplateAdd) {
          const { id, entity_type } = response.fintelTemplateAdd;
          MESSAGING$.notifySuccess(t_i18n('FINTEL template created'));
          navigate(`${resolveLink(entity_type)}/${entityType}/templates/${id}`);
        }
      },
      onError: (error) => {
        setSubmitting?.(false);
        handleError(error);
      },
    });
  };

  const onAdd: FormikConfig<FintelTemplateFormInputs>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    if (values.default && currentDefaultName) {
      setSubmitting(false);
      setPendingDefault({ kind: 'create', values });
    } else {
      doAdd(values, setSubmitting);
    }
  };

  const onEdit = (field: FintelTemplateFormInputKeys, value: unknown) => {
    if (!template) return;

    let input: { key: string; value: [unknown] } = { key: field, value: [value] };
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
          editingProps={template ? { onDefaultToggle: handleDefaultToggle } : undefined}
          defaultValues={template}
        />
      </Drawer>

      <FintelTemplateReplaceDefaultDialog
        open={!!pendingDefault}
        onClose={() => {
          if (pendingDefault?.kind === 'edit') pendingDefault.revert();
          setPendingDefault(null);
        }}
        onConfirm={() => {
          if (pendingDefault?.kind === 'create') doAdd(pendingDefault.values);
          else if (pendingDefault?.kind === 'edit') {
            commitEditMutation({
              variables: { id: template!.id, input: [{ key: 'default', value: ['true'] }] },
              onError: handleError,
            });
          }
          setPendingDefault(null);
        }}
        currentDefaultName={currentDefaultName ?? ''}
      />
    </>
  );
};

export default FintelTemplateFormDrawer;
