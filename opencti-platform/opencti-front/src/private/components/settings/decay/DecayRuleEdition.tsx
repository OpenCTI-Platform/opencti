import React, { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import { Field, FieldArray, Form, Formik } from 'formik';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import * as Yup from 'yup';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { AddOutlined, Delete } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import { InformationOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import { FormikConfig } from 'formik/dist/types';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import MarkdownField from '../../../../components/MarkdownField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import SwitchField from '../../../../components/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useAuth from '../../../../utils/hooks/useAuth';
import { handleError } from '../../../../relay/environment';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    paddingTop: 4,
    paddingRight: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
}));

export const decayRuleEditionMutation = graphql`
  mutation DecayRuleEditionMutation($id: ID!, $input: [EditInput!]!) {
    decayRuleFieldPatch(id: $id, input: $input) {
      ...DecayRule_decayRule
    }
  }
`;

interface DecayRuleEditionFormData {
  name: string
  description: string
  order: number
  active: boolean
  decay_lifetime: number
  decay_pound: number
  decay_points: number[]
  decay_revoke_score: number
  decay_observable_types: string[]
}

interface DecayRuleEditionFormProps {
  decayRuleId: string;
  initialValues: DecayRuleEditionFormData;
  onCompleted?: () => void;
}
const DecayRuleEditionForm: FunctionComponent<DecayRuleEditionFormProps> = ({
  decayRuleId,
  initialValues,
  onCompleted,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [commitUpdate] = useMutation(decayRuleEditionMutation);
  const { schema } = useAuth();
  const { scos } = schema;
  const allObservableTypes = scos.map((sco) => sco.id);

  const decayRuleValidator = Yup.object().shape({
    name: Yup.string().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    active: Yup.boolean(),
    order: Yup.number().min(1),
    decay_lifetime: Yup.number().min(1),
    decay_pound: Yup.number().min(0),
    decay_revoke_score: Yup.number().min(0),
    decay_observable_types: Yup.array().of(Yup.string()),
    decay_points: Yup.array().of(Yup.number().min(0)),
  });

  const handleSubmitField = (name: string, value: string | string[] | number | number[] | null) => {
    decayRuleValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: decayRuleId,
            input: { key: name, value: value || '' },
          },
          onCompleted: () => {
            if (onCompleted) {
              onCompleted();
            }
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
      validationSchema={decayRuleValidator}
      onSubmit={onSubmit}
    >
      {({ values }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
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
          <Field
            component={AutocompleteField}
            name="decay_observable_types"
            multiple={true}
            fullWidth={true}
            textfieldprops={{
              variant: 'standard',
              label: t_i18n('Apply on indicator observable types'),
            }}
            options={allObservableTypes}
            isOptionEqualToValue={(option: string, value: string) => option === value}
            style={{ marginTop: 20 }}
            onChange={handleSubmitField}
            renderOption={(
              props: React.HTMLAttributes<HTMLLIElement>,
              option: string,
            ) => (
              <li {...props}>
                <div className={classes.icon}>
                  <ItemIcon type={option} />
                </div>
                <ListItemText primary={t_i18n(`entity_${option}`)} />
              </li>
            )}
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
                  values.decay_points.map((decay_point, index) => (
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
      variant={DrawerVariant.updateWithPanel}
    >
      <DecayRuleEditionForm
        decayRuleId={decayRule.id}
        initialValues={initialValues}
      />
    </Drawer>
  );
};

export default DecayRuleEdition;
