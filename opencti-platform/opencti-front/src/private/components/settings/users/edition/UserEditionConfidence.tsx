import React, { FunctionComponent } from 'react';
import UserConfidenceLevelField from '@components/settings/users/edition/UserConfidenceLevelField';
import { UserEdition_user$data } from '@components/settings/users/__generated__/UserEdition_user.graphql';
import { Field, FieldArray, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import { userMutationFieldPatch } from '@components/settings/users/edition/UserEditionOverview';
import ConfidenceOverrideField from '@components/settings/users/edition/ConfidenceOverrideField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { useFormatter } from '../../../../../components/i18n';
import { isEmptyField, isNotEmptyField } from '../../../../../utils/utils';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

export interface OverrideFormData {
  max_confidence: string;
  entity_type: string;
}

export interface ConfidenceFormData {
  user_confidence_level_enabled: boolean;
  user_confidence_level: number | null | undefined;
  overrides: OverrideFormData[];
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

const userConfidenceValidation = (t: (value: string) => string) => {
  const maxConfidenceValidator = Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'))
    .when('user_confidence_level_enabled', {
      is: true,
      then: (schema) => schema.required(t('This field is required')).nullable(),
      otherwise: (schema) => schema.nullable(),
    });

  return Yup.object().shape({
    user_confidence_level_enabled: Yup.boolean(),
    user_confidence_level: maxConfidenceValidator,
    overrides: Yup.array().of(
      Yup.object().shape({
        entity_type: Yup.string(),
        max_confidence: maxConfidenceValidator,
      }),
    ),
  });
};

const UserEditionConfidence: FunctionComponent<UserEditionConfidenceProps> = ({ user, context }) => {
  const { t_i18n } = useFormatter();

  const initialValues: ConfidenceFormData = {
    user_confidence_level_enabled: !!user.user_confidence_level,
    user_confidence_level: user.user_confidence_level?.max_confidence,
    overrides: user.user_confidence_level?.overrides?.map((override) => ({
      ...override,
      max_confidence: override.max_confidence.toString(),
    })) ?? [] };

  const [commitFieldPatch] = useApiMutation(userMutationFieldPatch);

  const handleSubmitMaxConfidence = (name: string, value: string | null) => {
    userConfidenceValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        let finalValue;
        let object_path;
        if (user.user_confidence_level && isNotEmptyField(value)) {
          // we are updating the value
          object_path = '/user_confidence_level/max_confidence';
          finalValue = parseInt(value, 10);
        } else if (!user.user_confidence_level && value) {
          // We have no user_confidence_level, and we add one: push a complete object
          object_path = '/user_confidence_level';
          finalValue = {
            max_confidence: parseInt(value, 10),
            overrides: [],
          };
        } else if (user.user_confidence_level && !value) {
          // we have an existing value, but we want to remove it: push [null] (and not null!)
          object_path = '/user_confidence_level/max_confidence';
          finalValue = [null];
        }
        if (finalValue) {
          commitFieldPatch({
            variables: {
              id: user.id,
              input: {
                key: 'user_confidence_level',
                object_path,
                value: finalValue,
              },
            },
          });
        }
      })
      .catch(() => false);
  };

  const handleSubmitOverride = (index: number, value: OverrideFormData | null) => {
    if (isNotEmptyField(value?.entity_type) && isNotEmptyField(value?.max_confidence)) {
      let object_path = '';
      let finalValue;
      // If there is no user_confidence_level defined and value is provided, initialize it with an override
      if (!user.user_confidence_level) {
        object_path = 'user_confidence_level';
        finalValue = {
          max_confidence: null, // Initialize global max_confidence as null
          overrides: [{
            entity_type: value.entity_type,
            max_confidence: parseInt(value.max_confidence ?? '0', 10),
          }],
        };
      } else {
        // If user_confidence_level already exists, just update or add the override
        object_path = `/user_confidence_level/overrides/${index}`;
        finalValue = [{
          entity_type: value.entity_type,
          max_confidence: parseInt(value.max_confidence ?? '0', 10),
        }];
      }
      const name = `overrides[${index}]`;
      userConfidenceValidation(t_i18n)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: user.id,
              input: {
                key: 'user_confidence_level',
                object_path,
                value: finalValue,
              },
            },
          });
        })
        .catch(() => false);
    } else if (isEmptyField(value)) {
      commitFieldPatch({
        variables: {
          id: user.id,
          input: {
            key: 'user_confidence_level',
            operation: 'remove',
            object_path: `/user_confidence_level/overrides/${index}`,
            value: [null],
          },
        },
      });
    }
  };

  const defaultOverrideConfidence = user.effective_confidence_level && user.effective_confidence_level.max_confidence ? user.effective_confidence_level.max_confidence : 0;
  return (
    <>
      <Formik<ConfidenceFormData>
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={() => {}}
      >
        {({ values }) => (
          <Form>
            <UserConfidenceLevelField
              name="user_confidence_level"
              label={t_i18n('Max Confidence Level')}
              onSubmit={handleSubmitMaxConfidence}
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
                    onClick={() => arrayHelpers.push({ entity_type: '', max_confidence: defaultOverrideConfidence })}
                    style={{ marginTop: '5px' }}
                    disabled={values.overrides.some((o) => o.entity_type === '')}
                  >
                    <Add fontSize="small" />
                  </IconButton>
                  {values.overrides.map((_, idx) => (
                    <Field
                      // Field props
                      key={idx}
                      index={idx}
                      name={`overrides[${idx}]`}
                      // rendered components and its props
                      component={ConfidenceOverrideField}
                      onDelete={() => arrayHelpers.remove(idx)}
                      onSubmit={handleSubmitOverride}
                      currentOverrides={values.overrides}
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
