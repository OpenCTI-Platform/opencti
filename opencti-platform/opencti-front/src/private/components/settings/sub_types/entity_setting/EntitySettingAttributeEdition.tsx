import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik, FormikErrors, FormikValues } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import Drawer from '@components/common/drawer/Drawer';
import DefaultValueField from '@components/common/form/DefaultValueField';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import SwitchField from '../../../../../components/fields/SwitchField';
import type { Scale, ScaleConfig } from '../scale_configuration/scale';
import type { AttributeConfiguration } from './entitySetting';
import { EntitySettingAttributeLine_attribute$data } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import ScaleConfiguration from '../scale_configuration/ScaleConfiguration';
import { isCustomScale } from '../../../../../utils/hooks/useScale';
import { useComputeDefaultValues } from '../../../../../utils/hooks/useDefaultValues';
import { handleErrorInForm } from '../../../../../relay/environment';
import { DefaultValues, defaultValuesToStringArray } from '../../../../../utils/defaultValues';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

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
  default_values: Yup.mixed().nullable(),
});

interface AttributeFormikValues {
  mandatory: boolean;
  default_values: DefaultValues;
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
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const computeDefaultValues = useComputeDefaultValues();

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

  const [commit] = useApiMutation(entitySettingAttributeEditionPatch);

  const onSubmit: FormikConfig<AttributeFormikValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    const saveConfiguration = [...attributesConfiguration];
    const defaultValues = values.default_values;
    const default_values = defaultValuesToStringArray(defaultValues, attribute.name);

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

  const defaultValues = () => {
    const defaultValueAttribute = entitySetting.defaultValuesAttributes.find((element) => element.name === attribute.name);
    const attributeDefaultValues = defaultValueAttribute?.defaultValues ?? attribute.defaultValues;
    const values = attributeDefaultValues ? [...attributeDefaultValues] : [];
    return computeDefaultValues(
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
  const customScale = (values.scale && isCustomScale(values.scale)) ? values.scale : null;
  const text = attribute.label ?? attribute.name;
  const attributeName = t_i18n(text.charAt(0).toUpperCase() + text.slice(1));
  return (
    <Drawer
      title={`${t_i18n('Update the attribute')} "${attributeName}"`}
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
          <Form>
            <Field
              component={SwitchField}
              type="checkbox"
              name="mandatory"
              label={t_i18n('Mandatory')}
              disabled={attribute.mandatoryType !== 'customizable'}
            />

            <DefaultValueField
              attribute={attribute}
              setFieldValue={setFieldValue}
              entityType={entitySetting.target_type}
              name="default_values"
              disabled={!attribute.editDefault}
            />

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
                {t_i18n('Update')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default EntitySettingAttributeEdition;
