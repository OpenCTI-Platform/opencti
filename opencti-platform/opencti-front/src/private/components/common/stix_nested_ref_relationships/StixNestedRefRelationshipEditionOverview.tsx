import {
  StixNestedRefRelationshipEditionOverview_stixRefRelationship$key,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverview_stixRefRelationship.graphql';
import {
  StixNestedRefRelationshipEditionOverviewQuery,
} from '@components/common/stix_nested_ref_relationships/__generated__/StixNestedRefRelationshipEditionOverviewQuery.graphql';
import { useTheme } from '@mui/styles';
import { Field, Form, Formik } from 'formik';
import { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionFocus } from '../../../../components/Subscription';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import { buildDate } from '../../../../utils/Time';

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
  );
};

export default StixNestedRefRelationshipEditionOverview;
