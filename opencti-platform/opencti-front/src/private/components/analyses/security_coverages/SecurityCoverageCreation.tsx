import React, { FunctionComponent } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import StixCoreObjectsField from '@components/common/form/StixCoreObjectsField';
import { SecurityCoveragesLinesPaginationQuery$variables } from '@components/analyses/__generated__/SecurityCoveragesLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { insertNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const securityCoverageMutation = graphql`
  mutation SecurityCoverageCreationMutation($input: SecurityCoverageAddInput!) {
    securityCoverageAdd(input: $input) {
      id
      standard_id
      name
      description
      entity_type
      parent_types
      ...SecurityCoveragesLine_node
    }
  }
`;

const securityCoverageValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  objectCovered: Yup.object().required(t('This field is required')),
  coverage_information: Yup.array().of(
    Yup.object().shape({
      coverage_name: Yup.string().required(t('This field is required')),
      coverage_score: Yup.number()
        .required(t('This field is required'))
        .min(0, t('Score must be at least 0'))
        .max(100, t('Score must be at most 100')),
    }),
  ),
});

interface SecurityCoverageFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onClose?: () => void;
}

interface SecurityCoverageFormValues {
  name: string;
  description: string;
  createdBy: { value: string; label?: string } | null;
  objectMarking: { value: string }[];
  objectLabel: { value: string; label: string }[];
  objectCovered: { value: string; label?: string; entity_type?: string } | null;
  coverage_information: { coverage_name: string; coverage_score: number | string }[];
}

export const SecurityCoverageCreationForm: FunctionComponent<SecurityCoverageFormProps> = ({
  updater,
  onClose,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [commitMutation] = useApiMutation(securityCoverageMutation);

  const onSubmit: FormikConfig<SecurityCoverageFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const finalValues = {
      name: values.name,
      description: values.description,
      objectCovered: values.objectCovered?.value,
      coverage_information: values.coverage_information.map((info) => ({
        coverage_name: info.coverage_name,
        coverage_score: Number(info.coverage_score),
      })),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
    };

    commitMutation({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'securityCoverageAdd');
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onClose) {
          onClose();
        }
      },
    });
  };

  return (
    <Formik<SecurityCoverageFormValues>
      initialValues={{
        name: '',
        description: '',
        createdBy: null,
        objectMarking: [],
        objectLabel: [],
        objectCovered: null,
        coverage_information: [],
      }}
      validationSchema={securityCoverageValidation(t_i18n)}
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ values, isSubmitting, setFieldValue, handleReset, submitForm }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
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
            rows={4}
            style={fieldSpacingContainerStyle}
          />
          <StixCoreObjectsField
            name="objectCovered"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            multiple={false}
          />
          <FieldArray name="coverage_information">
            {({ remove, push }) => (
              <div style={{ marginTop: 20 }}>
                <Typography variant="h4">{t_i18n('Coverage Information')}</Typography>
                {values.coverage_information.map((_, index) => (
                  <div key={index} style={{ marginTop: 10 }}>
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`coverage_information.${index}.coverage_name`}
                      label={t_i18n('Coverage name')}
                      fullWidth={true}
                      style={{ marginBottom: 10 }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`coverage_information.${index}.coverage_score`}
                      label={t_i18n('Coverage score (0-100)')}
                      type="number"
                      fullWidth={true}
                    />
                    {values.coverage_information.length > 1 && (
                      <Button
                        variant="text"
                        color="primary"
                        onClick={() => remove(index)}
                        style={{ marginTop: 10 }}
                      >
                        {t_i18n('Remove')}
                      </Button>
                    )}
                  </div>
                ))}
                <Button
                  variant="text"
                  color="primary"
                  onClick={() => push({ coverage_name: '', coverage_score: '' })}
                  style={{ marginTop: 10 }}
                >
                  {t_i18n('Add coverage metric')}
                </Button>
              </div>
            )}
          </FieldArray>
          <CreatedByField
            name="createdBy"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

interface SecurityCoverageCreationProps {
  paginationOptions: SecurityCoveragesLinesPaginationQuery$variables;
}

const SecurityCoverageCreation: FunctionComponent<SecurityCoverageCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination__securityCoverages',
    paginationOptions,
    'securityCoverageAdd',
    null,
    null,
    null,
    null,
  );

  const CreateSecurityCoverageControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Security-Coverage' {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a security coverage')}
      controlledDial={CreateSecurityCoverageControlledDial}
    >
      <SecurityCoverageCreationForm updater={updater} />
    </Drawer>
  );
};

export default SecurityCoverageCreation;
