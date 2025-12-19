import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Field, FieldArray, Form, Formik } from 'formik';
import Drawer from '@components/common/drawer/Drawer';
import * as R from 'ramda';
import { AddOutlined, Delete } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import { InformationOutline } from 'mdi-material-ui';
import { FormikConfig } from 'formik/dist/types';
import ObservableTypesField from '@components/common/form/ObservableTypesField';
import decayRuleValidator from './DecayRuleValidator';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { handleError } from '../../../../relay/environment';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

export const decayRuleEditionMutation = graphql`
  mutation DecayRuleEditionMutation($id: ID!, $input: [EditInput!]!) {
    decayRuleFieldPatch(id: $id, input: $input) {
      ...DecayRule_decayRule
    }
  }
`;

interface DecayRuleEditionFormData {
  name: string;
  description: string;
  order: number;
  active: boolean;
  decay_lifetime: number;
  decay_pound: number;
  decay_points: number[];
  decay_revoke_score: number;
  decay_observable_types: string[];
}

interface DecayRuleEditionFormProps {
  decayRuleId: string;
  initialValues: DecayRuleEditionFormData;
}
const DecayRuleEditionForm: FunctionComponent<DecayRuleEditionFormProps> = ({
  decayRuleId,
  initialValues,
}) => {
  const { t_i18n } = useFormatter();
  const [commitUpdate] = useApiMutation(decayRuleEditionMutation);

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | null) => {
    decayRuleValidator(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: decayRuleId,
            input: { key: name, value: value || '' },
          },
          onError: (error: Error) => {
            handleError(error);
          },
        });
      })
      .catch(() => false);
  };

  const handleSubmitDecayPoints = (decayPoints: number[]) => {
    const decayPointsFiltered = R.uniq(decayPoints.map((p) => parseInt(String(p), 10)));
    decayPointsFiltered.sort().reverse();
    handleSubmitField('decay_points', decayPointsFiltered);
  };

  const onSubmit: FormikConfig<DecayRuleEditionFormData>['onSubmit'] = () => {};

  return (
    <Formik<DecayRuleEditionFormData>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={decayRuleValidator(t_i18n)}
      onSubmit={onSubmit}
    >
      {({ values }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={2}
            onSubmit={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          <ObservableTypesField
            name="decay_observable_types"
            label={t_i18n('Apply on indicator observable types (none = ALL)')}
            multiple={true}
            onChange={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_lifetime"
            label={t_i18n('Lifetime (in days)')}
            fullWidth={true}
            type="number"
            onSubmit={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_pound"
            label={t_i18n('Decay factor')}
            fullWidth={true}
            type="number"
            onSubmit={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          <FieldArray
            name="decay_points"
            render={(arrayHelpers) => (
              <div>
                <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <span>{t_i18n('Reaction points')}</span>
                    <Tooltip title={t_i18n('Define at which score thresholds the indicator is updated.')}>
                      <InformationOutline fontSize="small" color="primary" />
                    </Tooltip>
                    <Tooltip title={t_i18n('Add a reaction point')}>
                      <IconButton
                        color="primary"
                        aria-label="add"
                        onClick={() => arrayHelpers.push(0)}
                      >
                        <AddOutlined fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Typography>
                {values.decay_points && values.decay_points.length > 0 && (
                  values.decay_points.map((_, index) => (
                    <div key={index} style={{ display: 'flex' }}>
                      <div style={{ flex: 1 }}>
                        <Field
                          component={TextField}
                          variant="standard"
                          name={`decay_points.${index}`}
                          type="number"
                          fullWidth={true}
                          onSubmit={(name: string, value: number) => {
                            if (value) {
                              handleSubmitDecayPoints(values.decay_points ?? []);
                            }
                          }}
                        />
                      </div>
                      <div style={{ marginLeft: 10 }}>
                        <Tooltip title={t_i18n('Remove this reaction point')}>
                          <IconButton
                            color="primary"
                            aria-label="delete"
                            onClick={() => {
                              const value = arrayHelpers.remove(index);
                              const decayPoints = values.decay_points ?? [];
                              if (decayPoints.indexOf(value) >= 0) {
                                decayPoints.splice(decayPoints.indexOf(value), 1);
                              }
                              handleSubmitDecayPoints(decayPoints);
                            }}
                          >
                            <Delete fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_revoke_score"
            label={t_i18n('Revoke score')}
            fullWidth={true}
            type="number"
            onSubmit={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="order"
            label={t_i18n('Order')}
            fullWidth={true}
            type="number"
            onSubmit={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="active"
            label={t_i18n('Active')}
            onChange={handleSubmitField}
            containerstyle={fieldSpacingContainerStyle}
          />
        </Form>
      )}
    </Formik>
  );
};
interface DecayRuleEditionProps {
  decayRule: DecayRule_decayRule$data;
}

const DecayRuleEdition: FunctionComponent<DecayRuleEditionProps> = ({
  decayRule,
}) => {
  const { t_i18n } = useFormatter();
  const initialValues: DecayRuleEditionFormData = {
    name: decayRule.name,
    description: decayRule.description ?? '',
    order: decayRule.order,
    active: decayRule.active,
    decay_lifetime: decayRule.decay_lifetime,
    decay_pound: decayRule.decay_pound,
    decay_points: decayRule.decay_points ? [...decayRule.decay_points] : [],
    decay_revoke_score: decayRule.decay_revoke_score,
    decay_observable_types: decayRule.decay_observable_types ? [...decayRule.decay_observable_types] : [],
  };
  return (
    <Drawer
      title={t_i18n('Update a decay rule')}
      controlledDial={EditEntityControlledDial}
    >
      <DecayRuleEditionForm
        decayRuleId={decayRule.id}
        initialValues={initialValues}
      />
    </Drawer>
  );
};

export default DecayRuleEdition;
