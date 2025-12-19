import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { Field, FieldArray, Form, Formik, FormikConfig } from 'formik';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import Button from '@common/button/Button';
import * as R from 'ramda';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { AddOutlined, Delete } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import { InformationOutline } from 'mdi-material-ui';
import ObservableTypesField from '@components/common/form/ObservableTypesField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import SwitchField from '../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import { handleErrorInForm } from '../../../../relay/environment';
import decayRuleValidator from './DecayRuleValidator';
import { DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

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

const decayRuleCreationMutation = graphql`
  mutation DecayRuleCreationMutation($input: DecayRuleAddInput!) {
    decayRuleAdd(input: $input) {
      id
      name
      description
      created_at
      updated_at
      active
      order
      built_in
      appliedIndicatorsCount
    }
  }
`;

interface DecayRuleCreationFormData {
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

interface DecayRuleCreationFormProps {
  updater: (store: RecordSourceSelectorProxy) => void;
  onReset?: () => void;
  onCompleted?: () => void;
}
const DecayRuleCreationForm: FunctionComponent<DecayRuleCreationFormProps> = ({
  updater,
  onReset,
  onCompleted,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(decayRuleCreationMutation);

  const onSubmit: FormikConfig<DecayRuleCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const decayPoints = R.uniq(values.decay_points ?? []);
    const input = { // TODO type
      name: values.name,
      description: values.description,
      order: parseInt(String(values.order), 10),
      active: values.active,
      decay_lifetime: parseInt(String(values.decay_lifetime), 10),
      decay_pound: parseFloat(String(values.decay_pound)),
      decay_points: decayPoints.map((p) => parseInt(String(p), 10)),
      decay_revoke_score: parseInt(String(values.decay_revoke_score), 10),
      decay_observable_types: values.decay_observable_types ?? [],
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store);
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const initialValues: DecayRuleCreationFormData = {
    name: '',
    description: '',
    order: 1,
    active: false,
    decay_lifetime: 365,
    decay_pound: 1.0,
    decay_points: [],
    decay_revoke_score: 0,
    decay_observable_types: [],
  };

  return (
    <Formik<DecayRuleCreationFormData>
      initialValues={initialValues}
      validationSchema={decayRuleValidator(t_i18n)}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, values }) => (
        <Form>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={2}
            style={{ marginTop: 20 }}
          />
          <ObservableTypesField
            name="decay_observable_types"
            label={t_i18n('Apply on indicator observable types (none = ALL)')}
            multiple={true}
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_lifetime"
            label={t_i18n('Lifetime (in days)')}
            fullWidth={true}
            type="number"
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_pound"
            label={t_i18n('Decay factor')}
            fullWidth={true}
            type="number"
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
                  values.decay_points.map((decay_point, index) => (
                    <div key={index} style={{ display: 'flex' }}>
                      <div style={{ flex: 1 }}>
                        <Field
                          component={TextField}
                          variant="standard"
                          name={`decay_points.${index}`}
                          type="number"
                          fullWidth={true}
                        />
                      </div>
                      <div style={{ marginLeft: 10 }}>
                        <Tooltip title={t_i18n('Remove this reaction point')}>
                          <IconButton
                            color="primary"
                            aria-label="delete"
                            onClick={() => arrayHelpers.remove(index)}
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
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="order"
            label={t_i18n('Order')}
            fullWidth={true}
            type="number"
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="active"
            label={t_i18n('Active')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <div className={classes.buttons}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const CreateDecayRuleControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="DecayRule"
    {...props}
  />
);

interface DecayRuleCreationProps {
  paginationOptions: DecayRulesLinesPaginationQuery$variables;
}

const DecayRuleCreation: FunctionComponent<DecayRuleCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy) => {
    insertNode(
      store,
      'Pagination_decayRules',
      paginationOptions,
      'decayRuleAdd',
    );
  };

  return (
    <Drawer
      title={t_i18n('Create a decay rule')}
      controlledDial={CreateDecayRuleControlledDial}
    >
      {({ onClose }) => (
        <DecayRuleCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default DecayRuleCreation;
