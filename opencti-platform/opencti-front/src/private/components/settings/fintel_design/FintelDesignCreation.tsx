import React, { FunctionComponent } from 'react';
import { FintelDesignsLinesPaginationQuery$variables } from '@components/settings/fintel_design/__generated__/FintelDesignsLinesPaginationQuery.graphql';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import { useTheme } from '@mui/material';
import { FintelDesignCreationAddMutation } from '@components/settings/fintel_design/__generated__/FintelDesignCreationAddMutation.graphql';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { resolveLink } from '../../../../utils/Entity';
import type { Theme } from '../../../../components/Theme';

const fintelDesignCreationMutation = graphql`
  mutation FintelDesignCreationAddMutation($input: FintelDesignAddInput!) {
    fintelDesignAdd(input: $input) {
      id
      name
      ...FintelDesignsLine_node
    }
  }
`;

const CreateFintelDesignControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="FintelDesign"
    {...props}
  />
);

interface FintelDesignCreationFormData {
  name: string;
  description: string;
}

interface FintelDesignCreationFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined,
  ) => void;
  onReset?: () => void;
  onCompleted?: () => void;
}

const FintelDesignCreationForm: FunctionComponent<FintelDesignCreationFormProps> = ({
  updater,
  onReset,
  onCompleted,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [commit] = useApiMutation<FintelDesignCreationAddMutation>(fintelDesignCreationMutation);
  const onSubmit: FormikConfig<FintelDesignCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const input = {
      name: values.name,
      description: values.description,
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'fintelDesignAdd', response.fintelDesignAdd);
        }
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
        navigate(`${resolveLink('FintelDesign')}/${response.fintelDesignAdd?.id}`);
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const fintelDesignCreationValidator = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const initialValues: FintelDesignCreationFormData = {
    name: '',
    description: '',
  };

  return (
    <Formik<FintelDesignCreationFormData>
      initialValues={initialValues}
      validateOnBlur={false}
      validateOnChange={false}
      validationSchema={fintelDesignCreationValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form style={{ margin: theme.spacing(0) }}>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            required
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={2}
            style={{ marginTop: 20 }}
          />
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: 16 }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: 16 }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

interface FintelDesignCreationProps {
  paginationOptions: FintelDesignsLinesPaginationQuery$variables;
}

const FintelDesignCreation: FunctionComponent<FintelDesignCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_fintelDesigns',
    paginationOptions,
    'fintelDesignAdd',
  );

  return (
    <Drawer
      title={t_i18n('Create a fintel design')}
      controlledDial={CreateFintelDesignControlledDial}
    >
      {({ onClose }) => (
        <FintelDesignCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default FintelDesignCreation;
