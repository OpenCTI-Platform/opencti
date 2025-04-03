import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import { useNavigate } from 'react-router-dom';
import useHelper from 'src/utils/hooks/useHelper';
import { GroupingsLinesPaginationQuery$variables } from '@components/analyses/__generated__/GroupingsLinesPaginationQuery.graphql';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import { handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import CreatedByField from '../../common/form/CreatedByField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import OpenVocabField from '../../common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Option } from '../../common/form/ReferenceField';
import { GroupingCreationMutation, GroupingCreationMutation$variables } from './__generated__/GroupingCreationMutation.graphql';
import type { Theme } from '../../../../components/Theme';
import useDefaultValues from '../../../../utils/hooks/useDefaultValues';
import RichTextField from '../../../../components/fields/RichTextField';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

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

const groupingMutation = graphql`
  mutation GroupingCreationMutation($input: GroupingAddInput!) {
    groupingAdd(input: $input) {
      id
      standard_id
      name
      representative {
        main
      }
      description
      entity_type
      parent_types
      ...GroupingsLine_node
    }
  }
`;

const GROUPING_TYPE = 'Grouping';

interface GroupingAddInput {
  name: string;
  confidence: number | undefined;
  context: string;
  description: string;
  content: string;
  createdBy: Option | undefined;
  objectMarking: Option[];
  objectLabel: Option[];
  externalReferences: { value: string }[];
  file: File | undefined;
  authorized_members: {
    value: string,
    accessRight: string,
    groupsRestriction: {
      label: string,
      value: string,
      type: string
    }[] }[] | undefined;
}

interface GroupingFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
    response: { id: string; name: string } | null | undefined
  ) => void;
  onClose?: () => void;
  defaultCreatedBy?: { value: string; label: string };
  defaultMarkingDefinitions?: { value: string; label: string }[];
  defaultConfidence?: number;
  inputValue?: string;
}

export const GroupingCreationForm: FunctionComponent<GroupingFormProps> = ({
  updater,
  onClose,
  defaultConfidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  inputValue,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [mapAfter, setMapAfter] = useState<boolean>(false);
  const { mandatoryAttributes } = useIsMandatoryAttribute(GROUPING_TYPE);
  const canEditAuthorizedMembers = useGranted([KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2),
    confidence: Yup.number().nullable(),
    context: Yup.string(),
    description: Yup.string().nullable(),
    content: Yup.string().nullable(),
    createdBy: Yup.object().nullable(),
    objectMarking: Yup.array().nullable(),
    file: Yup.mixed().nullable(),
    authorized_members: Yup.array().nullable(),
  }, mandatoryAttributes);
  const validator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );
  const [commit] = useApiMutation<GroupingCreationMutation>(
    groupingMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Grouping')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<GroupingAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const input: GroupingCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      content: values.content,
      context: values.context,
      confidence: parseInt(String(values.confidence), 10),
      createdBy: values.createdBy?.value,
      objectMarking: values.objectMarking.map((v) => v.value),
      objectLabel: values.objectLabel.map((v) => v.value),
      externalReferences: values.externalReferences.map(({ value }) => value),
      file: values.file,
      ...(isEnterpriseEdition && canEditAuthorizedMembers && values.authorized_members && {
        authorized_members: values.authorized_members.map(({ value, accessRight, groupsRestriction }) => ({
          id: value,
          access_right: accessRight,
          groups_restriction_ids: groupsRestriction ? groupsRestriction.map((g) => g.value) : [],
        })),
      }),
    };
    commit({
      variables: {
        input,
      },
      updater: (store, response) => {
        if (updater && response) {
          updater(store, 'groupingAdd', response.groupingAdd);
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (onClose) {
          onClose();
        }
        if (mapAfter) {
          navigate(
            `/dashboard/analyses/groupings/${response.groupingAdd?.id}/content/mapping`,
          );
        }
      },
    });
  };

  const initialValues = useDefaultValues(GROUPING_TYPE, {
    name: inputValue ?? '',
    confidence: defaultConfidence,
    context: '',
    description: '',
    content: '',
    createdBy: defaultCreatedBy,
    objectMarking: defaultMarkingDefinitions ?? [],
    objectLabel: [],
    externalReferences: [],
    file: undefined,
    authorized_members: undefined,
  });
  if (!canEditAuthorizedMembers) {
    delete initialValues.authorized_members;
  }
  return (
    <Formik<GroupingAddInput>
      initialValues={initialValues}
      validationSchema={validator}
      validateOnChange={false} // Validation will occur on submission, required fields all have *'s
      validateOnBlur={false} // Validation will occur on submission, required fields all have *'s
      onSubmit={onSubmit}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            required={mandatoryAttributes.includes('name')}
            detectDuplicate={['Grouping']}
            fullWidth={true}
            askAi={true}
          />
          <ConfidenceField
            entityType="Grouping"
            containerStyle={fieldSpacingContainerStyle}
          />
          <OpenVocabField
            label={t_i18n('Context')}
            type="grouping-context-ov"
            name="context"
            required={mandatoryAttributes.includes('context')}
            multiple={false}
            containerStyle={fieldSpacingContainerStyle}
            onChange={setFieldValue}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            required={mandatoryAttributes.includes('description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
            askAi={true}
          />
          <Field
            component={RichTextField}
            name="content"
            label={t_i18n('Content')}
            required={mandatoryAttributes.includes('content')}
            fullWidth={true}
            style={{
              ...fieldSpacingContainerStyle,
              minHeight: 200,
              height: 200,
            }}
            askAi={true}
          />
          <CreatedByField
            name="createdBy"
            required={mandatoryAttributes.includes('createdBy')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            required={mandatoryAttributes.includes('objectLabel')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            required={mandatoryAttributes.includes('objectMarking')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
          />
          <ExternalReferencesField
            name="externalReferences"
            required={mandatoryAttributes.includes('externalReferences')}
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values.externalReferences}
          />
          <CustomFileUploader setFieldValue={setFieldValue} />
          {isEnterpriseEdition && (
            <Security
              needs={[KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]}
            >
              <div style={fieldSpacingContainerStyle}>
                <Accordion >
                  <AccordionSummary id="accordion-panel">
                    <Typography>{t_i18n('Advanced options')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Field
                      name={'authorized_members'}
                      component={AuthorizedMembersField}
                      containerstyle={{ marginTop: 20 }}
                      showAllMembersLine
                      canDeactivate
                      disabled={isSubmitting}
                      addMeUserWithAdminRights
                    />
                  </AccordionDetails>
                </Accordion>
              </div>
            </Security>
          )}
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
            {values.content.length > 0 && (
              <Button
                variant="contained"
                color="success"
                onClick={() => {
                  setMapAfter(true);
                  submitForm();
                }}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Create and map')}
              </Button>
            )}
          </div>
        </Form>
      )}
    </Formik>
  );
};

const GroupingCreation = ({
  paginationOptions,
}: {
  paginationOptions: GroupingsLinesPaginationQuery$variables;
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_groupings', paginationOptions, 'groupingAdd');
  const CreateGroupingControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='Grouping' {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a grouping')}
      variant={isFABReplaced ? undefined : DrawerVariant.create}
      controlledDial={isFABReplaced ? CreateGroupingControlledDial : undefined}
    >
      <GroupingCreationForm updater={updater} />
    </Drawer>
  );
};

export default GroupingCreation;
