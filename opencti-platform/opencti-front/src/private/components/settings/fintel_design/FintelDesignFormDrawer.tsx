import { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik, FormikConfig, FormikHelpers } from 'formik';
import * as Yup from 'yup';
import { useNavigate } from 'react-router-dom';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useTheme } from '@mui/material';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { FintelDesignFormDrawerAddMutation } from '@components/settings/fintel_design/__generated__/FintelDesignFormDrawerAddMutation.graphql';
import { FintelDesignFormDrawerFocusMutation } from '@components/settings/fintel_design/__generated__/FintelDesignFormDrawerFocusMutation.graphql';
import { FintelDesignsLinesPaginationQuery$variables } from '@components/settings/fintel_design/__generated__/FintelDesignsLinesPaginationQuery.graphql';
import Button from '@common/button/Button';
import FormButtonContainer from '@common/form/FormButtonContainer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fetchQuery, handleError, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import { FieldOption } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import FintelDesignReplaceDefaultDialog from './FintelDesignReplaceDefaultDialog';

const fintelDesignCreationMutation = graphql`
  mutation FintelDesignFormDrawerAddMutation($input: FintelDesignAddInput!) {
    fintelDesignAdd(input: $input) {
      id
      name
      ...FintelDesignsLine_node
    }
  }
`;

const fintelDesignEditionFocusMutation = graphql`
  mutation FintelDesignFormDrawerFocusMutation($id: ID! $input: EditContext!) {
    fintelDesignContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const fintelDesignEditionPatchMutation = graphql`
  mutation FintelDesignFormDrawerFieldPatchMutation($id: ID!, $input: [EditInput!]) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      id
      name
      description
      default
      ...FintelDesign_fintelDesign
    }
  }
`;

export const fintelDesignsCurrentDefaultQuery = graphql`
  query FintelDesignFormDrawerCurrentDefaultQuery {
    fintelDesigns(orderBy: name, orderMode: asc) {
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

interface FintelDesignFormValues {
  name: string;
  description: string;
  default: boolean;
}

interface PendingCreate {
  kind: 'create';
  values: FintelDesignFormValues;
  helpers: FormikHelpers<FintelDesignFormValues>;
}

interface PendingEdit {
  kind: 'edit';
  revert: () => void;
}

type PendingDefault = PendingCreate | PendingEdit;

export interface FintelDesignEditData {
  id: string;
  name: string;
  description: string | null;
  default: boolean;
}

const CreateFintelDesignControlledDial: DrawerControlledDialType = (props) => (
  <CreateEntityControlledDial entityType="FintelDesign" {...props} />
);

interface FintelDesignFormDrawerCreateProps {
  paginationOptions: FintelDesignsLinesPaginationQuery$variables;
  fintelDesign?: never;
  isOpen?: never;
  onClose?: never;
  controlledDial?: DrawerControlledDialType;
}

interface FintelDesignFormDrawerEditProps {
  fintelDesign: FintelDesignEditData;
  isOpen: boolean;
  onClose: () => void;
  paginationOptions?: never;
  controlledDial?: never;
}

type FintelDesignFormDrawerProps = FintelDesignFormDrawerCreateProps | FintelDesignFormDrawerEditProps;

const FintelDesignFormDrawer: FunctionComponent<FintelDesignFormDrawerProps> = (props) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();

  const isEditMode = !!props.fintelDesign;
  const fintelDesign = isEditMode ? props.fintelDesign : null;

  const [pendingDefault, setPendingDefault] = useState<PendingDefault | null>(null);
  const [currentDefaultName, setCurrentDefaultName] = useState<string | undefined>(undefined);

  const [commitAdd] = useApiMutation<FintelDesignFormDrawerAddMutation>(fintelDesignCreationMutation);
  const [commitFocus] = useApiMutation<FintelDesignFormDrawerFocusMutation>(fintelDesignEditionFocusMutation);
  const [commitPatch] = useApiMutation(fintelDesignEditionPatchMutation);

  const fetchExistingDefault = (excludeId?: string) => fetchQuery(fintelDesignsCurrentDefaultQuery, {})
    .toPromise()
    .then((res) => {
      const typed = res as {
        fintelDesigns?: {
          edges?: Array<{ node?: { id: string; name: string; default?: boolean } | null } | null>;
        };
      } | undefined;
      return typed?.fintelDesigns?.edges
        ?.map((e) => e?.node)
        .find((n) => n?.default && n.id !== excludeId);
    });

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_fintelDesigns',
    props.paginationOptions ?? {},
    'fintelDesignAdd',
  );

  const doCreate = (
    values: FintelDesignFormValues,
    helpers: FormikHelpers<FintelDesignFormValues>,
  ) => {
    commitAdd({
      variables: { input: { name: values.name, description: values.description, default: values.default } },
      updater: (store, response) => {
        if (response?.fintelDesignAdd) updater(store);
      },
      onCompleted: (response) => {
        helpers.setSubmitting(false);
        helpers.resetForm();
        navigate(`${resolveLink('FintelDesign')}/${response.fintelDesignAdd?.id}`);
      },
      onError: (error) => {
        handleErrorInForm(error, helpers.setErrors);
        helpers.setSubmitting(false);
      },
    });
  };

  const handleCreateSubmit: FormikConfig<FintelDesignFormValues>['onSubmit'] = (values, helpers) => {
    if (!values.default) {
      doCreate(values, helpers);
      return;
    }
    fetchExistingDefault()
      .then((existing) => {
        if (existing?.name) {
          setCurrentDefaultName(existing.name);
          setPendingDefault({ kind: 'create', values, helpers });
        } else {
          doCreate(values, helpers);
        }
      })
      .catch((err) => {
        handleErrorInForm(err as Error, helpers.setErrors);
        handleError(err as Error);
        helpers.setSubmitting(false);
      });
  };

  const refetchDesigns = () => {
    fetchQuery(fintelDesignsCurrentDefaultQuery, {}).toPromise().catch((err) => handleError(err));
  };

  const patchField = (name: string, value: FieldOption | string) => {
    commitPatch({
      variables: { id: fintelDesign!.id, input: [{ key: name, value: [value ?? ''] }] },
    });
  };

  const handleSetDefault = (revert: () => void) => {
    fetchExistingDefault(fintelDesign!.id)
      .then((existing) => {
        if (existing?.name) {
          setCurrentDefaultName(existing.name);
          setPendingDefault({ kind: 'edit', revert });
        } else {
          commitPatch({
            variables: { id: fintelDesign!.id, input: [{ key: 'default', value: [true] }] },
            onCompleted: refetchDesigns,
            onError: () => revert(),
          });
        }
      })
      .catch((err) => {
        handleError(err as Error);
        revert();
      });
  };

  const handleUnsetDefault = (revert: () => void) => {
    commitPatch({
      variables: { id: fintelDesign!.id, input: [{ key: 'default', value: [false] }] },
      onCompleted: refetchDesigns,
      onError: () => revert(),
    });
  };

  const handleDefaultToggle = (value: boolean, revert: () => void) => {
    if (value) handleSetDefault(revert);
    else handleUnsetDefault(revert);
  };

  const handleSubmitField = (name: string, value: FieldOption | string) => {
    patchField(name, value);
  };

  const handleClose = () => {
    if (isEditMode && fintelDesign) {
      commitFocus({ variables: { id: fintelDesign.id, input: { focusOn: '' } } });
    }
    props.onClose?.();
  };

  const title = isEditMode ? t_i18n('Update a Fintel design') : t_i18n('Create a fintel design');

  const initialValues: FintelDesignFormValues = {
    name: fintelDesign?.name ?? '',
    description: fintelDesign?.description ?? '',
    default: !!fintelDesign?.default,
  };

  const validator = Yup.object().shape({
    name: isEditMode
      ? Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters'))
      : Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  return (
    <>
      <Drawer
        title={title}
        open={isEditMode ? props.isOpen : undefined}
        onClose={handleClose}
        controlledDial={isEditMode ? undefined : (props.controlledDial ?? CreateFintelDesignControlledDial)}
      >
        {({ onClose: drawerOnClose }: { onClose: () => void }) => (
          <Formik<FintelDesignFormValues>
            enableReinitialize
            initialValues={initialValues}
            validationSchema={validator}
            validateOnChange={isEditMode}
            validateOnBlur={isEditMode}
            onSubmit={isEditMode ? () => {} : handleCreateSubmit}
          >
            {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
              <Form style={{ margin: theme.spacing(0) }}>
                <Field
                  component={TextField}
                  variant={isEditMode ? 'standard' : undefined}
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth
                  required={!isEditMode}
                  onSubmit={isEditMode ? handleSubmitField : undefined}
                />
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  fullWidth
                  multiline
                  rows={isEditMode ? '4' : 2}
                  style={{ marginTop: 20 }}
                  onSubmit={isEditMode ? handleSubmitField : undefined}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="default"
                  label={t_i18n('Set as default')}
                  containerstyle={{ marginTop: 20 }}
                  onChange={isEditMode
                    ? (_name: string, value: unknown) => {
                        const next = value === true || value === 'true';
                        handleDefaultToggle(next, () => setFieldValue('default', !next));
                      }
                    : undefined}
                />
                {!isEditMode && (
                  <FormButtonContainer>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        handleReset();
                        drawerOnClose();
                      }}
                      disabled={isSubmitting}
                    >
                      {t_i18n('Cancel')}
                    </Button>
                    <Button onClick={submitForm} disabled={isSubmitting}>
                      {t_i18n('Create')}
                    </Button>
                  </FormButtonContainer>
                )}
              </Form>
            )}
          </Formik>
        )}
      </Drawer>

      <FintelDesignReplaceDefaultDialog
        open={!!pendingDefault}
        onClose={() => {
          if (pendingDefault?.kind === 'create') pendingDefault.helpers.setSubmitting(false);
          if (pendingDefault?.kind === 'edit') pendingDefault.revert();
          setPendingDefault(null);
        }}
        onConfirm={() => {
          if (pendingDefault?.kind === 'create') {
            const { values, helpers } = pendingDefault;
            setPendingDefault(null);
            doCreate(values, helpers);
          } else if (pendingDefault?.kind === 'edit') {
            const { revert } = pendingDefault;
            setPendingDefault(null);
            commitPatch({
              variables: { id: fintelDesign!.id, input: [{ key: 'default', value: [true] }] },
              onCompleted: refetchDesigns,
              onError: () => revert(),
            });
          }
        }}
        currentDefaultName={currentDefaultName ?? ''}
      />
    </>
  );
};

export default FintelDesignFormDrawer;
