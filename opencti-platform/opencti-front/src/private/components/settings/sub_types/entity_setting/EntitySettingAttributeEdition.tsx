import React, { useEffect, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik, FormikErrors, FormikValues } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { head } from 'ramda';
import Drawer from '@components/common/drawer/Drawer';
import { EntitySettingAttributeEditionMembersQuery$data } from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingAttributeEditionMembersQuery.graphql';
import DefaultValueField from '@components/common/form/DefaultValueField';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import SwitchField from '../../../../../components/SwitchField';
import type { Scale, ScaleConfig } from '../scale_configuration/scale';
import type { AttributeConfiguration } from './entitySetting';
import { EntitySettingAttributeLine_attribute$data } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import ScaleConfiguration from '../scale_configuration/ScaleConfiguration';
import { isCustomScale } from '../../../../../utils/hooks/useScale';
import { Option } from '../../../common/form/ReferenceField';
import { useComputeDefaultValues } from '../../../../../utils/hooks/useDefaultValues';
import { fetchQuery, handleErrorInForm } from '../../../../../relay/environment';
import { AccessRight, INPUT_AUTHORIZED_MEMBERS } from '../../../../../utils/authorizedMembers';
import { defaultValuesToStringArray } from '../../../../../utils/defaultValues';

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
  query EntitySettingAttributeEditionMembersQuery($filters: FilterGroup) {
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
            mode: 'and',
            filters: [{
              key: 'ids',
              values: defaultAuthorizedMembers.map((m) => m.id),
            }],
            filterGroups: [],
          },
        }).toPromise()) as EntitySettingAttributeEditionMembersQuery$data;
        setMembersData(data);
      };
      fetchMembers();
    }
  }, [attribute]);

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
    const values = attribute.defaultValues ? [...attribute.defaultValues] : [];
    // Handle object marking specific case : activate or deactivate default values (handle in access)
    if (attribute.name === 'objectMarking') {
      return head(values)?.id ?? false;
    }
    return computeDefaultValues(
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
          <Form style={{ margin: '20px 0 20px 0' }}>
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
