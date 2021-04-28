import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc,
  compose,
  map,
  pathOr,
  pipe,
  pick,
  difference,
  head,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
});

const cityMutationFieldPatch = graphql`
  mutation CityEditionOverviewFieldPatchMutation($id: ID!, $input: EditInput!) {
    cityEdit(id: $id) {
      fieldPatch(input: $input) {
        ...CityEditionOverview_city
        ...City_city
      }
    }
  }
`;

export const cityEditionOverviewFocus = graphql`
  mutation CityEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    cityEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const cityMutationRelationAdd = graphql`
  mutation CityEditionOverviewRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    cityEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CityEditionOverview_city
        }
      }
    }
  }
`;

const cityMutationRelationDelete = graphql`
  mutation CityEditionOverviewRelationDeleteMutation(
    $id: ID!
    $toId: String!
    $relationship_type: String!
  ) {
    cityEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CityEditionOverview_city
      }
    }
  }
`;

const cityValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class CityEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: cityEditionOverviewFocus,
      variables: {
        id: this.props.city.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    cityValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: cityMutationFieldPatch,
          variables: { id: this.props.city.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedBy(name, value) {
    const { city } = this.props;
    const currentCreatedBy = {
      label: pathOr(null, ['createdBy', 'name'], city),
      value: pathOr(null, ['createdBy', 'id'], city),
    };

    if (currentCreatedBy.value === null) {
      commitMutation({
        mutation: cityMutationRelationAdd,
        variables: {
          id: this.props.city.id,
          input: {
            toId: value.value,
            relationship_type: 'created-by',
          },
        },
      });
    } else if (currentCreatedBy.value !== value.value) {
      commitMutation({
        mutation: cityMutationRelationDelete,
        variables: {
          id: this.props.city.id,
          toId: currentCreatedBy.value,
          relationship_type: 'created-by',
        },
      });
      if (value.value) {
        commitMutation({
          mutation: cityMutationRelationAdd,
          variables: {
            id: this.props.city.id,
            input: {
              toId: value.value,
              relationship_type: 'created-by',
            },
          },
        });
      }
    }
  }

  handleChangeObjectMarking(name, values) {
    const { city } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(city);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: cityMutationRelationAdd,
        variables: {
          id: this.props.city.id,
          input: {
            toId: head(added).value,
            relationship_type: 'object-marking',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: cityMutationRelationDelete,
        variables: {
          id: this.props.city.id,
          toId: head(removed).value,
          relationship_type: 'object-marking',
        },
      });
    }
  }

  render() {
    const { t, city, context } = this.props;
    const createdBy = pathOr(null, ['createdBy', 'name'], city) === null
      ? ''
      : {
        label: pathOr(null, ['createdBy', 'name'], city),
        value: pathOr(null, ['createdBy', 'id'], city),
      };
    const objectMarking = pipe(
      pathOr([], ['objectMarking', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
      })),
    )(city);
    const initialValues = pipe(
      assoc('createdBy', createdBy),
      assoc('objectMarking', objectMarking),
      pick(['name', 'description', 'createdBy', 'objectMarking']),
    )(city);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={cityValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            <CreatedByField
              name="createdBy"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdBy" />
              }
              onChange={this.handleChangeCreatedBy.bind(this)}
            />
            <ObjectMarkingField
              name="objectMarking"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldname="objectMarking"
                />
              }
              onChange={this.handleChangeObjectMarking.bind(this)}
            />
          </Form>
        )}
      </Formik>
    );
  }
}

CityEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  city: PropTypes.object,
  context: PropTypes.array,
};

const CityEditionOverview = createFragmentContainer(
  CityEditionOverviewComponent,
  {
    city: graphql`
      fragment CityEditionOverview_city on City {
        id
        name
        description
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              definition_type
            }
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CityEditionOverview);
