import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import {
  StixNestedRefRelationshipEditionOverview_stixRefRelationship$key,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverview_stixRefRelationship.graphql';
import {
  StixNestedRefRelationshipEditionOverviewQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverviewQuery.graphql';
import { buildDate } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars, SubscriptionFocus } from '../../../../components/Subscription';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import type { Theme } from '../../../../components/Theme';

const StixNestedRefRelationshipEditionFragment = graphql`
  fragment StixNestedRefRelationshipEditionOverview_stixRefRelationship on StixRefRelationship {
    id
    start_time
    stop_time
    relationship_type
    creators {
      id
      name
    }
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

export const stixNestedRefRelationshipEditionQuery = graphql`
  query StixNestedRefRelationshipEditionOverviewQuery($id: String!) {
    stixRefRelationship(id: $id) {
      ...StixNestedRefRelationshipEditionOverview_stixRefRelationship
    }
  }
`;

interface StixNestedRefRelationshipEditionOverviewProps {
  handleClose?: () => void;
  queryRef: PreloadedQuery<StixNestedRefRelationshipEditionOverviewQuery>;
}

const StixNestedRefRelationshipEditionOverview: FunctionComponent<StixNestedRefRelationshipEditionOverviewProps> = ({
  handleClose,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { stixRefRelationship } = usePreloadedQuery<StixNestedRefRelationshipEditionOverviewQuery>(
    stixNestedRefRelationshipEditionQuery,
    queryRef,
  );
  const stixRefRelationshipData = useFragment<StixNestedRefRelationshipEditionOverview_stixRefRelationship$key>(
    StixNestedRefRelationshipEditionFragment,
    stixRefRelationship,
  );
  if (!stixRefRelationshipData) {
    return (
      <div> &nbsp; </div>
    );
  }
  const [commitChangeFocus] = useApiMutation(stixRefRelationshipEditionFocus);
  const [commitSubmitField] = useApiMutation(stixNestedRefRelationshipMutationFieldPatch);

  const basicShape = {
    start_time: Yup.date().nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
    stop_time: Yup.date().nullable()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .min(
        Yup.ref('start_time'),
        "The end date can't be before the start date",
      ),
  };
  const stixNestedRefRelationshipValidator = useSchemaEditionValidation('stix-ref-relationship', basicShape);

  const handleChangeFocus = (name: string) => {
    commitChangeFocus({
      variables: {
        id: stixRefRelationshipData.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string) => {
    commitSubmitField({
      variables: {
        id: stixRefRelationshipData.id,
        input: { key: name, value: value || '' },
      },
    });
  };

  const { editContext } = stixRefRelationshipData;
  const initialValues = {
    start_time: buildDate(stixRefRelationshipData.start_time),
    stop_time: buildDate(stixRefRelationshipData.stop_time),
  };
  return (
    <>
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
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography
          variant="h6"
          style={{
            float: 'left',
          }}
        >
          {t_i18n('Update a relationship')}
        </Typography>
        <SubscriptionAvatars context={editContext} />
        <div className="clearfix" />
      </div>
      <div style={{
        padding: '10px 20px 20px 20px',
      }}
      >
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixNestedRefRelationshipValidator}
          onSubmit={() => {}}
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
    </>
  );
};

export default StixNestedRefRelationshipEditionOverview;
