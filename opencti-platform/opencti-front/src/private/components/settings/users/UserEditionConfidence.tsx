import React, { FunctionComponent, useEffect, useState } from 'react';
import UserConfidenceLevelField from '@components/settings/users/UserConfidenceLevelField';
import { UserEdition_user$data } from '@components/settings/users/__generated__/UserEdition_user.graphql';
import { Field, FieldArray, Form, Formik, useFormikContext } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import { useMutation } from 'react-relay';
import { userEditionOverviewFocus, userMutationFieldPatch } from '@components/settings/users/UserEditionOverview';
import UserConfidenceOverridesField from '@components/settings/users/UserConfidenceOverridesField';
import { Option } from '@components/common/form/ReferenceField';
import { FormikHelpers } from 'formik/dist/types';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';

export interface Override {
  max_confidence: number;
  entity_type: string;
}

interface ConfidenceFormData {
  user_confidence_level_enabled: boolean;
  user_confidence_level: number | null | undefined;
  overrides: Override[]
}

export interface AvailableEntityOption extends Option {
  type: string;
  id: string;
}

interface UserEditionConfidenceProps {
  user: UserEdition_user$data;
  context:
  | readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[]
  | null | undefined;
}

const userConfidenceValidation = (t: (value: string) => string) => Yup.object().shape({
  user_confidence_level_enabled: Yup.boolean(),
  user_confidence_level: Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'))
    .when('user_confidence_level_enabled', {
      is: true,
      then: (schema) => schema.required(t('This field is required')).nullable(),
      otherwise: (schema) => schema.nullable(),
    }),
});

const UserEditionConfidence: FunctionComponent<UserEditionConfidenceProps> = ({ user, context }) => {
  const { t_i18n } = useFormatter();
  const { schema } = useAuth();

  const [availableEntityTypes, setAvailableEntityTypes] = useState<
  AvailableEntityOption[]
  >([]);

  // load the available types once in state
  // TODO: Create a hook to call EntityTypes (useEntityTypes remix)
  useEffect(() => {
    const { sdos, scos, smos } = schema;
    const entityTypes = sdos
      .map((sdo) => ({
        ...sdo,
        value: sdo.id,
        type: 'entity_Stix-Domain-Objects',
      }))
      .concat(
        scos.map((sco) => ({
          ...sco,
          value: sco.id,
          type: 'entity_Stix-Cyber-Observables',
        })),
      )
      .concat(
        smos.map((smo) => ({
          ...smo,
          value: smo.id,
          type: 'entity_Stix-Meta-Objects',
        })),
      );
    setAvailableEntityTypes(entityTypes);
  }, [schema]);

  const initialValues: ConfidenceFormData = {
    user_confidence_level_enabled: !!user.user_confidence_level,
    user_confidence_level: user.user_confidence_level?.max_confidence,
    overrides: [...user.user_confidence_level?.overrides ?? []],
  };

  const onAddOverrideEntity = (
    setFieldValue: FormikHelpers<ConfidenceFormData>['setFieldValue'],
    values: ConfidenceFormData,
  ) => {
    setFieldValue('overrides', [...values.overrides, { entity_type: '', max_confidence: 0 }]);
  };

  const [commitFocus] = useMutation(userEditionOverviewFocus);
  const [commitFieldPatch] = useMutation(userMutationFieldPatch);

  const handleChangeFocus = (name: string) => {
    commitFocus({
      variables: {
        id: user.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string | null) => {
    userConfidenceValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        console.log('name', name, 'value', value)
        // specific case for user confidence level: to update an object we have several use-cases
        if (name === 'user_confidence_level') {
          if (user.user_confidence_level && value) {
            // We edit an existing value inside the object: use object_path
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  object_path: '/user_confidence_level/max_confidence',
                  value: parseInt(value, 10),
                },
              },
            });
          } else if (!user.user_confidence_level && value) {
            // We have no user_confidence_level and we add one: push a complete object
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  object_path: '/user_confidence_level/max_confidence',
                  value: {
                    max_confidence: parseInt(value, 10),
                    overrides: [],
                  },
                },
              },
            });
          } else if (user.user_confidence_level && !value) {
            // we have an existing value but we want to remove it: push [null] (and not null!)
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  object_path: '/user_confidence_level/max_confidence',
                  value: [null],
                },
              },
            });
          }
        } else {
          // simple case for all flat attributes
          commitFieldPatch({
            variables: {
              id: user.id,
              input: { key: name, value: value || '' },
            },
          });
        }
      })
      .catch(() => false);
  };

  return (
    <>
      <Formik<ConfidenceFormData>
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={() => {}}
      >
        {({ values, setFieldValue }) => (
          <Form>
            <UserConfidenceLevelField
              name="user_confidence_level"
              label={t_i18n('Max Confidence Level')}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              user={user}
            />

            <FieldArray
              name="overrides"
              render={(arrayHelpers) => (
                <div>
                  <Typography variant="h4" gutterBottom={true} style={{ float: 'left', marginTop: '20px' }}>
                    {t_i18n('Add a specific max confidence level for an entity type')}
                  </Typography>
                  <IconButton
                    color="primary"
                    aria-label="Add"
                    onClick={() => onAddOverrideEntity(setFieldValue, values)}
                    style={{ marginTop: '5px' }}
                    size="large"
                  >
                    <Add fontSize="small" />
                  </IconButton>

                  {values.overrides.map((_, idx) => (

                    <Field
                      key={idx}
                      component={UserConfidenceOverridesField}
                      name={`overrides[${idx}]`}
                      index={idx}
                      availableTypes={availableEntityTypes}
                      prefixLabel="entity_"
                      onDelete={() => arrayHelpers.remove(idx)}
                      onSubmit={handleSubmitField}
                    />
                  ))}
                </div>
              )}
            />
          </Form>
        )}
      </Formik>
    </>
  );
};

export default UserEditionConfidence;
