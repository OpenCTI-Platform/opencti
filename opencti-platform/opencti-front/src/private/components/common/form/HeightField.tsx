import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@common/button/Button';
import { IconButton } from '@mui/material';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data,
} from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import { MeasureInput } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualCreationMutation.graphql';
import { GenericContext } from '../model/GenericContextModel';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import useUserMetric from '../../../../utils/hooks/useUserMetric';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { isNotEmptyField } from '../../../../utils/utils';

export const individualHeightMutation = graphql`
  mutation HeightFieldIndividualMutation($id: ID!, $input: [EditInput]!) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      height {
        index
        measure
        date_seen
      }
    }
  }
`;

interface HeightFieldEditProps {
  id: string;
  name: string;
  values: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$data['height'];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
  editContext?: readonly (GenericContext | null)[] | null;
}
export const HeightFieldEdit: FunctionComponent<HeightFieldEditProps> = ({
  name,
  id,
  values,
  containerStyle,
  editContext = [],
}): ReactElement => {
  const { t_i18n } = useFormatter();
  const { lengthPrimaryUnit, heightToPivotFormat } = useUserMetric();
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <div id="total_height_read">
            {(values ?? []).map((height, index) => {
              return (
                <div
                  key={index}
                  style={{ marginTop: 20, width: '100%', position: 'relative' }}
                >
                  <div
                    style={{
                      paddingRight: 50,
                      display: 'grid',
                      gap: 20,
                      gridTemplateColumns: 'repeat(2, 1fr)',
                    }}
                  >
                    <Field
                      component={TextField}
                      variant="standard"
                      type="number"
                      slotProps={{ input: { min: 0 } }}
                      name={`${name}.${index}.measure`}
                      label={t_i18n(`Height (${lengthPrimaryUnit})`)}
                      onSubmit={(_: string, measure: string) => {
                        if (isNotEmptyField(measure)) {
                          commitMutation({
                            ...defaultCommitMutation,
                            mutation: individualHeightMutation,
                            variables: {
                              id,
                              input: {
                                key: 'height',
                                value: [heightToPivotFormat(measure)],
                                object_path: `/height/${height.index}/measure`,
                                operation: 'replace',
                              },
                            },
                          });
                        }
                      }}
                    />
                    <Field
                      component={DateTimePickerField}
                      id={`height_date_${index}`}
                      name={`${name}.${index}.date_seen`}
                      onSubmit={(_: string, date_seen: string) => {
                        if (isNotEmptyField(date_seen)) {
                          commitMutation({
                            ...defaultCommitMutation,
                            mutation: individualHeightMutation,
                            variables: {
                              id,
                              input: {
                                key: 'height',
                                value: [date_seen],
                                object_path: `/height/${height.index}/date_seen`,
                                operation: 'replace',
                              },
                            },
                          });
                        }
                      }}
                      textFieldProps={{
                        label: t_i18n('Date Seen'),
                        variant: 'standard',
                        helperText: (
                          <SubscriptionFocus
                            context={editContext}
                            fieldName={`${name}.${index}.date_seen`}
                          />
                        ),
                      }}
                    />
                  </div>
                  <IconButton
                    id="deleteHeight"
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                      commitMutation({
                        ...defaultCommitMutation,
                        mutation: individualHeightMutation,
                        variables: {
                          id,
                          input: {
                            key: 'height',
                            object_path: `/height/${height.index}`,
                            value: [],
                            operation: 'remove',
                          },
                        },
                      });
                    }}
                    style={{ position: 'absolute', right: -10, top: 5 }}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </div>
              );
            })}
            <Button
              size="small"
              startIcon={<AddOutlined />}
              aria-label="Add"
              id="addHeight"
              onClick={() => {
                const newHeight = { measure: 0, date_seen: new Date().toISOString() };
                arrayHelpers.push(newHeight);
                commitMutation({
                  ...defaultCommitMutation,
                  mutation: individualHeightMutation,
                  variables: {
                    id,
                    input: {
                      key: 'height',
                      value: [newHeight],
                      operation: 'add',
                    },
                  },
                });
              }}
              style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
            >
              {t_i18n('Add a height')}
            </Button>
          </div>
        )}
      />
    </div>
  );
};

interface HeightFieldAddProps {
  id: string;
  name: string;
  values: MeasureInput[];
  containerStyle: { marginTop: number; width: string };
  setFieldValue?: (name: string, value: unknown) => void;
}
export const HeightFieldAdd: FunctionComponent<HeightFieldAddProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t_i18n } = useFormatter();
  const { lengthPrimaryUnit } = useUserMetric();
  return (
    <div style={containerStyle}>
      <FieldArray
        name={name}
        render={(arrayHelpers) => (
          <>
            <div id="total_height_read">
              {values?.map((_, index) => (
                <div
                  key={index}
                  style={{ marginTop: 20, width: '100%', position: 'relative' }}
                >
                  <div
                    style={{
                      paddingRight: 50,
                      display: 'grid',
                      gap: 20,
                      gridTemplateColumns: 'repeat(2, 1fr)',
                    }}
                  >
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`${name}.${index}.measure`}
                      label={t_i18n(`Height (${lengthPrimaryUnit})`)}
                      type="number"
                      slotProps={{ input: { min: 0 } }}
                    />
                    <Field
                      component={DateTimePickerField}
                      name={`${name}.${index}.date_seen`}
                      textFieldProps={{
                        label: t_i18n('Date Seen'),
                        variant: 'standard',
                      }}
                      type="date"
                    />
                  </div>
                  <IconButton
                    id="deleteHeight"
                    aria-label="Delete"
                    onClick={() => {
                      arrayHelpers.remove(index);
                    }}
                    style={{ position: 'absolute', right: -10, top: 5 }}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </div>
              ))}
              <Button
                size="small"
                startIcon={<AddOutlined />}
                aria-label="Add"
                id="addHeight"
                onClick={() => {
                  arrayHelpers.push({ measure: 0, date_seen: new Date().toISOString() });
                }}
                style={{ marginTop: (values?.length ?? 0) > 0 ? 20 : 0 }}
              >
                {t_i18n('Add a height')}
              </Button>
            </div>
          </>
        )}
      />
    </div>
  );
};
