import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';

import IngestionSchedulingField from '../IngestionSchedulingField';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { insertNode } from '../../../../utils/store';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import FormButtonContainer from '@common/form/FormButtonContainer';
import IngestionCreationUserHandling from '@components/data/IngestionCreationUserHandling';
import { IngestionRssImportQuery$data } from '@components/data/__generated__/IngestionRssImportQuery.graphql';
import { PaginationOptions } from '../../../../components/list_lines';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const ingestionRssCreationValidation = () => {
  const { t_i18n } = useFormatter();

  return Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    object_marking_refs: Yup.array().nullable(),
    report_types: Yup.array().nullable(),
    created_by_ref: Yup.object().nullable(),
    user_id: Yup.object().nullable(),
    current_state_date: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
  });
};

const CreateIngestionRssControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="IngestionRss"
    {...props}
  />
);

interface IngestionRssAddInput {
  name: string;
  description?: string;
  scheduling_period?: string;
  uri: string;
  object_marking_refs?: { label: string; value: string }[];
  report_types?: string[];
  created_by_ref?: FieldOption;
  current_state_date?: Date;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
}

const IngestionRssCreationMutation = graphql`
  mutation IngestionRssCreationMutation($input: IngestionRssAddInput!) {
    ingestionRssAdd(input: $input) {
      ...IngestionRssLine_node
    }
  }
`;

interface IngestionRssCreationProps {
  paginationOptions?: PaginationOptions;
  handleClose?: () => void;
  ingestionRssData?: IngestionRssImportQuery$data['ingestionRssAddInputFromImport'];
  triggerButton?: boolean;
  open?: boolean;
  drawerSettings?: {
    title: string;
    button: string;
  };
}

const IngestionRssCreation: FunctionComponent<IngestionRssCreationProps> = ({ paginationOptions,
  handleClose,
  ingestionRssData,
  triggerButton = true,
  open = false,
  drawerSettings,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(IngestionRssCreationMutation);
  const handleSubmit = (values: IngestionRssAddInput, { setSubmitting, resetForm }: FormikHelpers<IngestionRssAddInput>) => {
    const userId
      = typeof values.user_id === 'object'
        ? values.user_id?.value
        : values.user_id;
    const input = {
      name: values.name,
      description: values.description,
      scheduling_period: values.scheduling_period,
      uri: values.uri,
      report_types: values.report_types,
      user_id: userId,
      automatic_user: values.automatic_user ?? true,
      current_state_date: values.current_state_date,
      created_by_ref: values.created_by_ref?.value,
      object_marking_refs: values.object_marking_refs?.map((v) => v.value),
      ...((values.automatic_user !== false) && { confidence_level: Number(values.confidence_level) }),
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_ingestionRsss', paginationOptions, 'ingestionRssAdd');
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const initialValues: IngestionRssAddInput = {
    name: ingestionRssData?.name || '',
    description: ingestionRssData?.description || '',
    scheduling_period: ingestionRssData?.scheduling_period || '',
    uri: ingestionRssData?.uri || '',
    report_types: ingestionRssData?.report_types
      ? [...ingestionRssData.report_types]
      : [],
    user_id: '',
    automatic_user: true,
    current_state_date: ingestionRssData?.current_state_date ? new Date(ingestionRssData.current_state_date) : undefined,
    created_by_ref: undefined,
    object_marking_refs: ingestionRssData?.object_marking_refs
      ? ingestionRssData.object_marking_refs
          .filter((v): v is { label: string; value: string } => Boolean(v))
      : [],
  };

  return (
    <Drawer
      title={drawerSettings?.title ?? t_i18n('Create a RSS ingester')}
      open={open}
      onClose={handleClose}
      controlledDial={triggerButton ? CreateIngestionRssControlledDial : undefined}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={ingestionRssCreationValidation()}
          onSubmit={handleSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <IngestionSchedulingField />
              <Field
                component={TextField}
                variant="standard"
                name="uri"
                label={t_i18n('RSS Feed URL')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <IngestionCreationUserHandling
                default_confidence_level={50}
                labelTag="F"
              />
              <Field
                component={DateTimePickerField}
                name="current_state_date"
                textFieldProps={{
                  label: t_i18n(
                    'Import from date (empty = all RSS feed possible items)',
                  ),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <OpenVocabField
                label={t_i18n('Default report types')}
                type="report_types_ov"
                name="report_types"
                onChange={(name, value) => setFieldValue(name, value)}
                containerStyle={fieldSpacingContainerStyle}
                multiple={true}
              />
              <CreatedByField
                name="created_by_ref"
                label={t_i18n('Default author')}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                label={t_i18n('Default marking definitions')}
                name="object_marking_refs"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <FormButtonContainer>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {drawerSettings?.button ?? t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default IngestionRssCreation;
