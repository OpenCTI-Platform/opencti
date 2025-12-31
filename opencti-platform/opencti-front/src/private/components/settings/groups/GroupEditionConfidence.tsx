import React, { FunctionComponent } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import * as Yup from 'yup';
import ConfidenceOverrideField from '@components/settings/users/edition/ConfidenceOverrideField';
import { createFragmentContainer, graphql } from 'react-relay';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { GroupEditionConfidence_group$data } from './__generated__/GroupEditionConfidence_group.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { useFormatter } from '../../../../components/i18n';
import { isEmptyField, isNotEmptyField } from '../../../../utils/utils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const groupConfidenceMutationFieldPatch = graphql`
  mutation GroupEditionConfidenceFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    groupEdit(id: $id) {
      fieldPatch(input: $input) {
        ...GroupEditionConfidence_group
      }
    }
  }
`;
export interface OverrideFormData {
  max_confidence: string;
  entity_type: string;
}

export interface ConfidenceFormData {
  group_confidence_level: number | null | undefined;
  overrides: OverrideFormData[];
}

interface GroupEditionConfidenceProps {
  group: GroupEditionConfidence_group$data;
  context:
    | readonly ({
      readonly focusOn: string | null | undefined;
      readonly name: string;
    } | null)[]
    | null | undefined;
}

const groupConfidenceValidation = (t: (value: string) => string) => {
  const maxConfidenceValidator = Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'));

  return Yup.object().shape({
    group_confidence_level: maxConfidenceValidator,
    overrides: Yup.array().of(
      Yup.object().shape({
        entity_type: Yup.string(),
        max_confidence: maxConfidenceValidator,
      }),
    ),
  });
};

const GroupEditionConfidenceComponent: FunctionComponent<GroupEditionConfidenceProps> = ({ group, context }) => {
  const { t_i18n } = useFormatter();

  const initialValues: ConfidenceFormData = {
    group_confidence_level: group.group_confidence_level?.max_confidence,
    overrides: group.group_confidence_level?.overrides?.map((override) => ({
      ...override,
      max_confidence: override.max_confidence.toString(),
    })) ?? [] };

  const [commitFieldPatch] = useApiMutation(groupConfidenceMutationFieldPatch);

  const handleSubmitMaxConfidence = (name: string, value: string) => {
    groupConfidenceValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        if (name === 'group_confidence_level') {
          if (group.group_confidence_level) {
            commitFieldPatch({
              variables: {
                id: group.id,
                input: {
                  key: 'group_confidence_level',
                  object_path: '/group_confidence_level/max_confidence',
                  value: parseInt(value, 10),
                },
              },
            });
          } else {
            commitFieldPatch({
              variables: {
                id: group.id,
                input: {
                  key: 'group_confidence_level',
                  value: {
                    max_confidence: parseInt(value, 10),
                    overrides: [],
                  },
                },
              },
            });
          }
        }
      })
      .catch(() => false);
  };

  const handleSubmitOverride = (index: number, value: OverrideFormData | null) => {
    if (isNotEmptyField(value?.entity_type) && isNotEmptyField(value?.max_confidence)) {
      const object_path = `/group_confidence_level/overrides/${index}`;
      const finalValue = [{
        entity_type: value.entity_type,
        max_confidence: parseInt(value.max_confidence ?? '0', 10),
      }];
      const name = `overrides[${index}]`;
      groupConfidenceValidation(t_i18n)
        .validateAt(name, { [name]: value })
        .then(() => {
          commitFieldPatch({
            variables: {
              id: group.id,
              input: {
                key: 'group_confidence_level',
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
          id: group.id,
          input: {
            key: 'group_confidence_level',
            operation: 'remove',
            object_path: `/group_confidence_level/overrides/${index}`,
            value: [null],
          },
        },
      });
    }
  };

  return (
    <>
      <Formik<ConfidenceFormData>
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={() => {}}
      >
        {({ values }) => (
          <Form>
            <ConfidenceField
              name="group_confidence_level"
              label={t_i18n('Max Confidence Level')}
              onSubmit={handleSubmitMaxConfidence}
              entityType="Group"
              containerStyle={fieldSpacingContainerStyle}
              editContext={context}
              variant="edit"
              disabled={false}
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
                    onClick={() => arrayHelpers.push({ entity_type: '', max_confidence: group.group_confidence_level?.max_confidence })}
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

const GroupEditionConfidence = createFragmentContainer(
  GroupEditionConfidenceComponent,
  {
    group: graphql`
      fragment GroupEditionConfidence_group on Group {
        id
        group_confidence_level {
          max_confidence
          overrides {
            max_confidence
            entity_type
          }
        }
        ...GroupHiddenTypesField_group
      }
    `,
  },
);
export default GroupEditionConfidence;
