import { useState } from 'react';
import { type FormikConfig } from 'formik';
import { useNavigate } from 'react-router-dom';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../../components/i18n';
import { fetchQuery as relayFetchQuery } from 'react-relay';
import { environment, handleError, MESSAGING$ } from '../../../../../relay/environment';
import useCustomViewEdit from './useCustomViewEdit';
import useCustomViewAdd from './useCustomViewAdd';
import CustomViewForm, { type CustomViewFormInputs } from './CustomViewForm';
import CustomViewReplaceDefaultDialog from './CustomViewReplaceDefaultDialog';
import { graphql } from 'react-relay';

const customViewCurrentDefaultQuery = graphql`
  query CustomViewFormDrawerCurrentDefaultQuery($entityType: String!) {
    customViews(entityType: $entityType, first: 5, orderBy: default, orderMode: desc) {
      edges {
        node {
          id
          name
          default
        }
      }
    }
  }
`;

type PendingDefault =
  | { kind: 'create'; values: CustomViewFormInputs }
  | { kind: 'edit'; revert: () => void };

interface CustomViewFormDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  entityType: string;
  customView?: { id: string } & CustomViewFormInputs;
}

const CustomViewFormDrawer = ({
  isOpen,
  onClose,
  entityType,
  customView,
}: CustomViewFormDrawerProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const createTitle = t_i18n('Create custom view');
  const editionTitle = t_i18n('Update custom view');
  const isEdition = !!customView;

  const commitAddMutation = useCustomViewAdd();
  const [commitEditMutation] = useCustomViewEdit();
  const [currentDefaultName, setCurrentDefaultName] = useState('');
  const [pendingDefault, setPendingDefault] = useState<PendingDefault | null>(null);

  const fetchExistingDefault = (entityType_: string, excludeId?: string) => relayFetchQuery(environment, customViewCurrentDefaultQuery, { entityType: entityType_ }, { fetchPolicy: 'network-only' })
    .toPromise()
    .then((result: unknown) => {
      const data = result as { customViews?: { edges: { node: { id: string; name: string; default: boolean } }[] } };
      return data.customViews?.edges.map((e) => e.node).find((n) => n.default && n.id !== excludeId);
    });

  const handleSetDefault = (revert: () => void) => {
    fetchExistingDefault(entityType, customView?.id)
      .then((existing) => {
        if (existing) {
          setCurrentDefaultName(existing.name);
          setPendingDefault({ kind: 'edit', revert });
        } else {
          commitEditMutation({
            variables: { id: customView!.id, input: [{ key: 'default', value: [true] }] },
            onError: () => { MESSAGING$.notifyError(t_i18n('Failed to update custom view')); revert(); },
          });
        }
      })
      .catch((err) => { handleError(err); revert(); });
  };

  const handleUnsetDefault = (revert: () => void) => {
    commitEditMutation({
      variables: { id: customView!.id, input: [{ key: 'default', value: [false] }] },
      onError: () => { MESSAGING$.notifyError(t_i18n('Failed to update custom view')); revert(); },
    });
  };

  const handleDefaultToggle = (value: boolean, revert: () => void) => {
    if (value) handleSetDefault(revert);
    else handleUnsetDefault(revert);
  };

  const doAdd = (values: CustomViewFormInputs, setSubmitting?: (isSubmitting: boolean) => void) => {
    commitAddMutation({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          targetEntityType: entityType,
          default: values.default,
        },
      },
      onCompleted: (response) => {
        setSubmitting?.(false);
        onClose();
        if (response.customViewAdd) {
          const { id } = response.customViewAdd;
          navigate(`/dashboard/settings/customization/entity_types/${entityType}/custom-views/${id}`);
        }
      },
      onError: (error) => {
        setSubmitting?.(false);
        handleError(error);
      },
    });
  };

  const handleSubmitForm: FormikConfig<CustomViewFormInputs>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    if (isEdition) {
      setSubmitting(false);
      return;
    }

    if (values.default) {
      fetchExistingDefault(entityType)
        .then((existing) => {
          if (existing) {
            setCurrentDefaultName(existing.name);
            setSubmitting(false);
            setPendingDefault({ kind: 'create', values });
          } else {
            doAdd(values, setSubmitting);
          }
        })
        .catch((err) => {
          setSubmitting(false);
          handleError(err);
        });
    } else {
      doAdd(values, setSubmitting);
    }
  };

  const handleEditField = (
    field: string,
    value: unknown,
    { setSubmitting }: { setSubmitting: (isSubmitting: boolean) => void },
  ) => {
    if (!isEdition) {
      setSubmitting(false);
      return;
    }
    const input: { key: string; value: [unknown] } = { key: field, value: [value] };
    commitEditMutation({
      variables: { id: customView.id, input: [input] },
      onCompleted: () => { setSubmitting(false); },
      onError: () => {
        setSubmitting(false);
        MESSAGING$.notifyError(t_i18n('Failed to update custom view'));
      },
    });
  };

  const title = isEdition ? editionTitle : createTitle;

  return (
    <>
      <Drawer
        title={title}
        open={isOpen}
        onClose={onClose}
      >
        <CustomViewForm
          onClose={onClose}
          onSubmit={handleSubmitForm}
          onSubmitField={handleEditField}
          editingProps={isEdition ? {onDefaultToggle: handleDefaultToggle}: undefined}
          values={customView}
        />
      </Drawer>

      <CustomViewReplaceDefaultDialog
        open={!!pendingDefault}
        onClose={() => {
          if (pendingDefault?.kind === 'edit') pendingDefault.revert();
          setPendingDefault(null);
        }}
        onConfirm={() => {
          if (pendingDefault?.kind === 'create') doAdd(pendingDefault.values);
          else if (pendingDefault?.kind === 'edit') {
            commitEditMutation({
              variables: { id: customView!.id, input: [{ key: 'default', value: [true] }] },
              onError: () => MESSAGING$.notifyError(t_i18n('Failed to update custom view')),
            });
          }
          setPendingDefault(null);
        }}
        currentDefaultName={currentDefaultName}
      />
    </>
  );
};

export default CustomViewFormDrawer;
