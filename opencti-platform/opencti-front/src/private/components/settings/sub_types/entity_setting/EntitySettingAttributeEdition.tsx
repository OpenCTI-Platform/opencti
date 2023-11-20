import React, { useEffect, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik, FormikErrors, FormikValues } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { head } from 'ramda';
import Alert from '@mui/lab/Alert/Alert';
import Drawer from '@components/common/drawer/Drawer';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import { EntitySettingAttributeEditionMembersQuery$data } from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingAttributeEditionMembersQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import { Theme } from '../../../../../components/Theme';
import SwitchField from '../../../../../components/SwitchField';
import TextField from '../../../../../components/TextField';
import { Scale, ScaleConfig } from '../scale_configuration/scale';
import { AttributeConfiguration } from './entitySetting';
import { EntitySettingAttributeLine_attribute$data } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import ScaleConfiguration from '../scale_configuration/ScaleConfiguration';
import { isCustomScale } from '../../../../../utils/hooks/useScale';
import OpenVocabField from '../../../common/form/OpenVocabField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { Option } from '../../../common/form/ReferenceField';
import CreatedByField from '../../../common/form/CreatedByField';
import { useComputeDefaultValues } from '../../../../../utils/hooks/useDefaultValues';
import useVocabularyCategory from '../../../../../utils/hooks/useVocabularyCategory';
import MarkdownField from '../../../../../components/MarkdownField';
import ObjectAssigneeField from '../../../common/form/ObjectAssigneeField';
import RichTextField from '../../../../../components/RichTextField';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import KillChainPhasesField from '../../../common/form/KillChainPhasesField';
import ObjectParticipantField from '../../../common/form/ObjectParticipantField';
import { fetchQuery, handleErrorInForm } from '../../../../../relay/environment';
import { AccessRight, INPUT_AUTHORIZED_MEMBERS } from '../../../../../utils/authorizedMembers';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const entitySettingAttributeEditionPatch = graphql`
  mutation EntitySettingAttributeEditionPatchMutation(
    $ids: [ID!]!
    $input: [EditInput!]!
  ) {
    entitySettingsFieldPatch(ids: $ids, input: $input) {
      ...EntitySettingAttributes_entitySetting
    }
  }
`;

const entitySettingAttributeEditionMembersQuery = graphql`
  query EntitySettingAttributeEditionMembersQuery($filters: [MembersFiltering]) {
    members(filters: $filters) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
  }
`;

const attributeValidation = () => Yup.object().shape({
  mandatory: Yup.boolean().nullable(),
  default_values: Yup.mixed().nullable(),
});

interface AttributeFormikValues {
  mandatory: boolean;
  default_values: string | string[] | Option | Option[] | boolean | null;
  scale: ScaleConfig;
}

interface AttributeSubmitValues {
  mandatory?: boolean;
  default_values: string[] | null;
  scale?: { local_config: ScaleConfig };
}

interface EntitySettingAttributeEditionProps {
  attribute: EntitySettingAttributeLine_attribute$data
  handleClose: () => void
  entitySetting: EntitySettingAttributes_entitySetting$data
  open?: boolean
}

const EntitySettingAttributeEdition = ({
  attribute,
  handleClose,
  entitySetting,
  open,
}: EntitySettingAttributeEditionProps) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { fieldToCategory } = useVocabularyCategory();
  const ovCategory = fieldToCategory(entitySetting.target_type, attribute.name);

  const attributesConfiguration: AttributeConfiguration[] = entitySetting.attributes_configuration
    ? JSON.parse(entitySetting.attributes_configuration)
    : [];
  const getScaleConfig = (attributeScale: string) => {
    const scale = JSON.parse(attributeScale) as Scale;
    return scale.local_config;
  };
  const [scaleErrors, setScaleErrors] = useState<FormikErrors<FormikValues>>(
    {},
  );

  const [commit] = useMutation(entitySettingAttributeEditionPatch);

  const [membersData, setMembersData] = useState<EntitySettingAttributeEditionMembersQuery$data>();

  useEffect(() => {
    if (attribute.name === INPUT_AUTHORIZED_MEMBERS) {
      const defaultAuthorizedMembers: { id: string, access_right: AccessRight }[] = (attribute.defaultValues ?? [])
        .map((v) => JSON.parse(v.id))
        .filter((v) => !!v.id && !!v.access_right);

      const fetchMembers = async () => {
        // Old way to fetch query here because doing it new way is a bit complicated
        // due to the fact that this component managed all types of fields and this
        // query is used only for one particular case.
        const data = (await fetchQuery(entitySettingAttributeEditionMembersQuery, {
          filters: {
            key: 'id',
            values: defaultAuthorizedMembers.map((m) => m.id),
          },
        }).toPromise()) as EntitySettingAttributeEditionMembersQuery$data;
        setMembersData(data);
      };
      fetchMembers();
    }
  }, []);

  const isBoolean = (defaultValues: string | boolean | Option) => {
    return typeof defaultValues === 'boolean';
  };

  const isSingleOption = (defaultValues: string | boolean | Option) => {
    return (
      typeof defaultValues === 'object'
      && 'value' in (defaultValues as unknown as Option)
    );
  };

  const isMultipleOption = (defaultValues: string[] | Option[]) => {
    return defaultValues.some(isSingleOption);
  };

  const onSubmit: FormikConfig<AttributeFormikValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    const saveConfiguration = [...attributesConfiguration];
    const defaultValues = values.default_values;
    let default_values: string[] | null = null;

    if (defaultValues) {
      if (Array.isArray(defaultValues)) {
        if (attribute.name === INPUT_AUTHORIZED_MEMBERS) {
          default_values = (defaultValues as Option[])
            .filter((v) => v.accessRight !== 'none')
            .map((v) => JSON.stringify({
              id: v.value,
              access_right: v.accessRight,
            }));
        } else if (isMultipleOption(defaultValues)) {
        // Handle multiple options
          default_values = defaultValues.map((v) => (v as Option).value);
        }
        // Handle single option
      } else if (isSingleOption(defaultValues)) {
        default_values = [(defaultValues as Option).value];
        // Handle single value
      } else if (isBoolean(defaultValues)) {
        default_values = [defaultValues.toString()];
      } else {
        // Default case -> string
        default_values = [defaultValues as string];
      }
    }

    const newValues: AttributeSubmitValues = {
      default_values,
    };
    if (attribute.mandatoryType === 'customizable') {
      newValues.mandatory = values.mandatory;
    }
    if (attribute.scale && values.scale) {
      newValues.scale = { local_config: values.scale };
    }

    const currentKeyIdx = saveConfiguration.findIndex(
      (a) => a.name === attribute.name,
    );
    if (currentKeyIdx > -1) {
      saveConfiguration[currentKeyIdx] = {
        ...saveConfiguration[currentKeyIdx],
        ...newValues,
      };
    } else {
      saveConfiguration.push({ name: attribute.name, ...newValues });
    }

    commit({
      variables: {
        ids: [entitySetting.id],
        input: {
          key: 'attributes_configuration',
          value: JSON.stringify(saveConfiguration),
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const field = (setFieldValue: (field: string, value: string) => void) => {
    const label = t('Default value');
    // Handle object marking specific case : activate or deactivate default values (handle in access)
    if (attribute.name === 'objectMarking') {
      return (
        <>
          <Field
            component={SwitchField}
            type="checkbox"
            name="default_values"
            label={t('Activate/Deactivate default values')}
            fullWidth={true}
            containerstyle={{ marginTop: 20 }}
          />
          <Alert
            severity="info"
            variant="outlined"
            style={{ margin: '20px 0 10px 0' }}
          >
            {t(
              'When enabling a default value for marking definitions, it will put the group default markings ot the user which created the entity if nothing is provided.',
            )}
          </Alert>
        </>
      );
    }
    if (attribute.name === 'killChainPhases') {
      return (
        <KillChainPhasesField
          name="default_values"
          style={fieldSpacingContainerStyle}
        />
      );
    }
    // Handle createdBy
    if (attribute.name === 'createdBy') {
      return (
        <CreatedByField
          label={label}
          name="default_values"
          style={fieldSpacingContainerStyle}
          setFieldValue={setFieldValue}
        />
      );
    }
    // Handle objectAssignee
    if (attribute.name === 'objectAssignee') {
      return (
        <ObjectAssigneeField
          label={label}
          name="default_values"
          style={fieldSpacingContainerStyle}
        />
      );
    }
    // Handle objectParticipant
    if (attribute.name === 'objectParticipant') {
      return (
        <ObjectParticipantField
          label={label}
          name="default_values"
          style={fieldSpacingContainerStyle}
        />
      );
    }
    // Handle authorized members
    if (attribute.name === INPUT_AUTHORIZED_MEMBERS) {
      return (
        <Field
          name="default_values"
          component={AuthorizedMembersField}
          style={fieldSpacingContainerStyle}
          showAllMembersLine
          showCreatorLine
          canDeactivate
        />
      );
    }
    // Handle multiple & single OV
    if (ovCategory) {
      return (
        <OpenVocabField
          label={label}
          type={ovCategory}
          name="default_values"
          multiple={attribute.multiple ?? false}
          containerStyle={fieldSpacingContainerStyle}
        />
      );
    }
    // Handle single numeric
    if (attribute.type === 'date') {
      return (
        <Field
          label={label}
          component={DateTimePickerField}
          name="default_values"
          TextFieldProps={{
            label,
            variant: 'standard',
            fullWidth: true,
            style: { marginTop: 20 },
          }}
        />
      );
    }
    // Handle single boolean
    if (attribute.type === 'boolean') {
      return (
        <Field
          component={SwitchField}
          type="checkbox"
          name="default_values"
          label={label}
          containerstyle={fieldSpacingContainerStyle}
        />
      );
    }
    // Handle single numeric
    if (attribute.type === 'numeric') {
      return (
        <Field
          component={TextField}
          type="number"
          variant="standard"
          name="default_values"
          label={label}
          fullWidth={true}
          style={{ marginTop: 20 }}
        />
      );
    }
    // Handle single string - Markdown
    if (attribute.name === 'description') {
      return (
        <Field
          component={MarkdownField}
          name="default_values"
          label={label}
          fullWidth={true}
          multiline={true}
          rows="4"
          style={{ marginTop: 20 }}
        />
      );
    }
    // Handle single string - Richtext
    if (attribute.name === 'content') {
      return (
        <Field
          component={RichTextField}
          name="default_values"
          label={label}
          fullWidth={true}
          style={{
            ...fieldSpacingContainerStyle,
            minHeight: 200,
            height: 200,
          }}
        />
      );
    }
    return (
      <Field
        component={TextField}
        variant="standard"
        name="default_values"
        label={label}
        fullWidth={true}
        style={{ marginTop: 20 }}
      />
    );
  };

  const defaultValues = () => {
    const values = attribute.defaultValues ? [...attribute.defaultValues] : [];
    // Handle object marking specific case : activate or deactivate default values (handle in access)
    if (attribute.name === 'objectMarking') {
      return head(values)?.id ?? false;
    }
    return useComputeDefaultValues(
      entitySetting.target_type,
      attribute.name,
      attribute.multiple ?? false,
      attribute.type,
      values,
      attribute.name === INPUT_AUTHORIZED_MEMBERS ? membersData : undefined,
    );
  };

  const values: AttributeFormikValues = {
    mandatory: attribute.mandatory,
    default_values: defaultValues(),
    scale: attribute.scale
      ? getScaleConfig(attribute.scale)
      : ({} as ScaleConfig),
  };
  const customScale = (values.scale && isCustomScale(values.scale)) ? values.scale : null;
  const text = attribute.label ?? attribute.name;
  const attributeName = t(text.charAt(0).toUpperCase() + text.slice(1));
  return (
    <Drawer
      title={`${t('Update the attribute')} "${attributeName}"`}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={values}
        validationSchema={attributeValidation()}
        onSubmit={onSubmit}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          initialValues,
          isValid,
        }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={SwitchField}
              type="checkbox"
              name="mandatory"
              label={t('Mandatory')}
              disabled={attribute.mandatoryType !== 'customizable'}
            />
            {field(setFieldValue)}
            {attribute.scale && (
              <ScaleConfiguration
                initialValues={initialValues.scale}
                fieldName="scale"
                setFieldValue={setFieldValue}
                setErrors={setScaleErrors}
                customScale={customScale}
                style={{ marginTop: 20 }}
              />
            )}
            <div className={classes.buttons}>
              <Button
                variant="contained"
                color="primary"
                onClick={submitForm}
                disabled={
                  isSubmitting
                  || !isValid
                  || Object.keys(scaleErrors).length > 0
                }
                classes={{ root: classes.button }}
              >
                {t('Update')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default EntitySettingAttributeEdition;
