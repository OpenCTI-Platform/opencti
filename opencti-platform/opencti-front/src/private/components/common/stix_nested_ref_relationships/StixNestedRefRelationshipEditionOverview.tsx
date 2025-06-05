import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import * as R from 'ramda';
import { useTheme } from '@mui/styles';
import { StixNestedRefRelationshipEditionQuery } from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionQuery.graphql';
import {
  StixNestedRefRelationshipEditionOverview_stixRefRelationship$key,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverview_stixRefRelationship.graphql';
import { buildDate } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { SubscriptionFocus } from '../../../../components/Subscription';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const StixNestedRefRelationshipEditionFragment = graphql`
  fragment StixNestedRefRelationshipEditionOverview_stixRefRelationship on StixRefRelationship {
    id
    start_time
    stop_time
    relationship_type
    editContext {
      name
      focusOn
    }
  }
`;

const stixNestedRefRelationshipMutationFieldPatch = graphql`
  mutation StixNestedRefRelationshipEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    stixRefRelationshipEdit(id: $id) {
      fieldPatch(input: $input) {
        ...StixNestedRefRelationshipEditionOverview_stixRefRelationship
      }
    }
  }
`;

export const stixRefRelationshipEditionFocus = graphql`
  mutation StixNestedRefRelationshipEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    stixRefRelationshipEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const stixNestedRefRelationshipValidation = (t) => Yup.object().shape({
  start_time: Yup.date().nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  stop_time: Yup.date().nullable()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .min(
      Yup.ref('start_time'),
      "The end date can't be before the start date",
    ),
});

export const stixNestedRefRelationshipEditionQuery = graphql`
  query StixNestedRefRelationshipEditionQuery($id: String!) {
    stixRefRelationship(id: $id) {
      ...StixNestedRefRelationshipEditionOverview_stixRefRelationship
    }
  }
`;

interface StixNestedRefRelationshipEditionOverviewProps {
  handleClose?: () => void,
  queryRef: PreloadedQuery<StixNestedRefRelationshipEditionQuery>,
}

const StixNestedRefRelationshipEditionOverview: FunctionComponent<StixNestedRefRelationshipEditionOverviewProps> = ({
  handleClose,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { stixRefRelationship } = usePreloadedQuery<StixNestedRefRelationshipEditionQuery>(
    stixNestedRefRelationshipEditionQuery,
    queryRef,
  );
  const stixRefRelationshipData = useFragment<StixNestedRefRelationshipEditionOverview_stixRefRelationship$key>(
    StixNestedRefRelationshipEditionFragment,
    stixRefRelationship,
  );

  const handleChangeFocus = (name: string) => {
    commitMutation({
      mutation: stixRefRelationshipEditionFocus,
      variables: {
        id: stixRefRelationshipData.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string) => {
    stixNestedRefRelationshipValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: stixNestedRefRelationshipMutationFieldPatch,
          variables: {
            id: stixRefRelationshipData.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };

  const { editContext } = stixRefRelationshipData;
  const killChainPhases = R.pipe(
    R.pathOr([], ['killChainPhases', 'edges']),
    R.map((n) => ({
      label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`,
      value: n.node.id,
    })),
  )(stixRefRelationshipData);
  const objectMarking = R.pipe(
    R.pathOr([], ['objectMarking', 'edges']),
    R.map((n) => ({
      label: n.node.definition,
      value: n.node.id,
    })),
  )(stixRefRelationshipData);
  const initialValues = R.pipe(
    R.assoc(
      'start_time',
      buildDate(stixRefRelationshipData.start_time),
    ),
    R.assoc(
      'stop_time',
      buildDate(stixRefRelationshipData.stop_time),
    ),
    R.assoc('killChainPhases', killChainPhases),
    R.assoc('objectMarking', objectMarking),
    R.pick(['start_time', 'stop_time', 'killChainPhases', 'objectMarking']),
  )(stixRefRelationshipData);
  return (
    <div>
      <div style={{
        backgroundColor: theme.palette.background.nav,
        padding: '20px 20px 20px 60px',
      }}
      >
        <IconButton
          aria-label="Close"
          style={{
            position: 'absolute',
            top: 12,
            left: 5,
            color: 'inherit',
          }}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" style={{
          float: 'left',
        }}
        >
          {t_i18n('Update a relationship')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div style={{
        padding: '10px 20px 20px 20px',
      }}
      >
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixNestedRefRelationshipValidation(t_i18n)}
          render={() => (
            <Form>
              <Field
                component={DateTimePickerField}
                name="start_time"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                textFieldProps={{
                  label: t_i18n('Start time'),
                  variant: 'standard',
                  fullWidth: true,
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="start_time"
                    />
                  ),
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time"
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                textFieldProps={{
                  label: t_i18n('Stop time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                  helperText: (
                    <SubscriptionFocus
                      context={editContext}
                      fieldName="stop_time"
                    />
                  ),
                }}
              />
            </Form>
          )}
        />
      </div>
    </div>
  );
};

export default StixNestedRefRelationshipEditionOverview;
