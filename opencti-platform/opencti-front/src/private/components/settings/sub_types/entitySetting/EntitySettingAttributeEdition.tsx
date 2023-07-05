import React, { useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik, FormikErrors, FormikValues } from 'formik';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { head } from 'ramda';
import Alert from '@mui/lab/Alert/Alert';
import { useFormatter } from '../../../../../components/i18n';
import { Theme } from '../../../../../components/Theme';
import SwitchField from '../../../../../components/SwitchField';
import TextField from '../../../../../components/TextField';
import { Scale, ScaleConfig } from '../scaleConfiguration/scale';
import { AttributeConfiguration } from './entitySetting';
import { EntitySettingAttributeLine_attribute$data } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import ScaleConfiguration from '../scaleConfiguration/ScaleConfiguration';
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

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
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

const attributeValidation = () => Yup.object().shape({
  mandatory: Yup.boolean().nullable(),
  default_values: Yup.array().nullable(),
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

const EntitySettingAttributeEdition = ({
  attribute,
  handleClose,
  entitySetting,
}: {
  attribute: EntitySettingAttributeLine_attribute$data;
  handleClose: () => void;
  entitySetting: EntitySettingAttributes_entitySetting$data;
}) => {
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
    { setSubmitting },
  ) => {
    const saveConfiguration = [...attributesConfiguration];
    const defaultValues:
    | string
    | boolean
    | Option
    | string[]
    | Option[]
    | null = values.default_values;
    let default_values: string[] | null = null;
    if (defaultValues) {
      if (Array.isArray(defaultValues)) {
        // Handle multiple options
        if (isMultipleOption(defaultValues)) {
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
    });
  };

  const field = () => {
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
    );
  };

  const values: AttributeFormikValues = {
    mandatory: attribute.mandatory,
    default_values: defaultValues(),
    scale: attribute.scale
      ? getScaleConfig(attribute.scale)
      : ({} as ScaleConfig),
  };
  const text = attribute.label ?? attribute.name;
  const attributeName = t(text.charAt(0).toUpperCase() + text.slice(1));
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {`${t('Update the attribute')} "${attributeName}"`}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
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
              {field()}
              {attribute.scale && (
                <ScaleConfiguration
                  initialValues={initialValues.scale}
                  fieldName="scale"
                  setFieldValue={setFieldValue}
                  setErrors={setScaleErrors}
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
      </div>
    </div>
  );
};

export default EntitySettingAttributeEdition;
