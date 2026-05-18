import React from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { useTheme } from '@mui/material/styles';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { Field, FieldArray, Form, Formik, FormikConfig } from 'formik';
import { handleErrorInForm } from '../../../../relay/environment';
import { emptyFilterGroup, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import decayRuleValidator from '@components/settings/decay/DecayRuleValidator';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import IconButton from '@common/button/IconButton';
import { AddOutlined, Delete } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Button from '@common/button/Button';
import Filters from '@components/common/lists/Filters';
import { enabledFilters } from './utils/enabledFilters';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import FilterIconButton from '../../../../components/FilterIconButton';

const decayRuleCreationFormAddMutation = graphql`
  mutation DecayRuleCreationFormAddMutation($input: DecayRuleAddInput!) {
    decayRuleAdd(input: $input) {
      ...DecayRulesLine_node
    }
  }
`;

type DecayRuleCreationFormProps = {
  updater: (store: RecordSourceSelectorProxy, rootField: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
};

type DecayRuleCreationFormData = {
  name: string;
  description: string;
  order: number;
  active: boolean;
  decay_lifetime: number;
  decay_pound: number;
  decay_points: number[];
  decay_revoke_score: number;
  decay_filters: string;
};

const DecayRuleCreationForm = ({ updater, onReset, onCompleted }: DecayRuleCreationFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [commit] = useApiMutation(decayRuleCreationFormAddMutation);
  const [filters, filterHelpers] = useFiltersState(emptyFilterGroup);

  const onSubmit: FormikConfig<DecayRuleCreationFormData>['onSubmit'] = (values, { setSubmitting, resetForm, setErrors }) => {
    const { name, description, order, active, decay_lifetime, decay_pound, decay_points, decay_revoke_score } = values;
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const input = {
      name,
      description,
      order: parseInt(String(order), 10),
      active,
      decay_lifetime: parseInt(String(decay_lifetime), 10),
      decay_pound: parseFloat(String(decay_pound)),
      decay_points: decay_points.map((point) => parseInt(String(point), 10)),
      decay_revoke_score: parseInt(String(decay_revoke_score), 10),
      decay_filters: jsonFilters,
    };

    commit({
      variables: { input },
      updater: (store) => {
        if (updater) {
          updater(store, 'decayRuleAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) onCompleted();
      },
      onError: (error) => {
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
    decay_filters: '',
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
            fullWidth
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth
            multiline
            rows={2}
            style={{ marginTop: 20 }}
          />
          <Box sx={{
            paddingTop: '30px',
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(1),
            marginBottom: theme.spacing(1),
          }}
          >
            <Filters
              availableFilterKeys={enabledFilters}
              helpers={filterHelpers}
              searchContext={{ entityTypes: ['Indicator'] }}
            />
          </Box>
          <FilterIconButton
            filters={filters}
            helpers={filterHelpers}
            searchContext={{ entityTypes: ['Indicator'] }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_lifetime"
            label={t_i18n('Lifetime (in days)')}
            fullWidth
            type="number"
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="decay_pound"
            label={t_i18n('Decay factor')}
            fullWidth
            type="number"
            style={{ marginTop: 20 }}
          />
          <FieldArray
            name="decay_points"
            render={(arrayHelpers) => (
              <div>
                <Typography variant="h3" gutterBottom style={{ marginTop: 20 }}>
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
                          fullWidth
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
            fullWidth
            type="number"
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="order"
            label={t_i18n('Order')}
            fullWidth
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
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
        </Form>
      )}
    </Formik>
  );
};

export default DecayRuleCreationForm;
