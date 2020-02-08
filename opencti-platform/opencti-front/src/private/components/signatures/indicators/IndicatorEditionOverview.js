import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
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
  union,
} from 'ramda';
import * as Yup from 'yup';
import inject18n from '../../../../components/i18n';
import Autocomplete from '../../../../components/Autocomplete';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import {
  commitMutation,
  fetchQuery,
  WS_ACTIVATED,
} from '../../../../relay/environment';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import AutocompleteCreate from '../../../../components/AutocompleteCreate';
import IdentityCreation, {
  identityCreationIdentitiesSearchQuery,
} from '../../common/identities/IdentityCreation';
import DatePickerField from '../../../../components/DatePickerField';

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

const indicatorMutationFieldPatch = graphql`
  mutation IndicatorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    indicatorEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IndicatorEditionOverview_indicator
      }
    }
  }
`;

export const indicatorEditionOverviewFocus = graphql`
  mutation IndicatorEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    indicatorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const indicatorMutationRelationAdd = graphql`
  mutation IndicatorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    indicatorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...IndicatorEditionOverview_indicator
        }
      }
    }
  }
`;

const indicatorMutationRelationDelete = graphql`
  mutation IndicatorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    indicatorEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...IndicatorEditionOverview_indicator
      }
    }
  }
`;

const indicatorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  valid_from: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  valid_until: Yup.date()
    .typeError(t('The value must be a date (YYYY-MM-DD)'))
    .required(t('This field is required')),
  score: Yup.number(),
  description: Yup.string(),
});

class IndicatorEditionOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      markingDefinitions: [],
      identityCreation: false,
      identities: [],
    };
  }

  searchIdentities(event) {
    fetchQuery(identityCreationIdentitiesSearchQuery, {
      search: event.target.value,
      first: 10,
    }).then((data) => {
      const identities = pipe(
        pathOr([], ['identities', 'edges']),
        map((n) => ({ label: n.node.name, value: n.node.id })),
      )(data);
      this.setState({ identities: union(this.state.identities, identities) });
    });
  }

  handleOpenIdentityCreation(inputValue) {
    this.setState({ identityCreation: true, identityInput: inputValue });
  }

  handleCloseIdentityCreation() {
    this.setState({ identityCreation: false });
  }

  searchMarkingDefinitions(event) {
    fetchQuery(markingDefinitionsLinesSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map((n) => ({ label: n.node.definition, value: n.node.id })),
      )(data);
      this.setState({
        markingDefinitions: union(
          this.state.markingDefinitions,
          markingDefinitions,
        ),
      });
    });
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: indicatorEditionOverviewFocus,
        variables: {
          id: this.props.indicator.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    indicatorValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: indicatorMutationFieldPatch,
          variables: {
            id: this.props.indicator.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { indicator } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], indicator),
      value: pathOr(null, ['createdByRef', 'node', 'id'], indicator),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], indicator),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: indicatorMutationRelationAdd,
        variables: {
          id: this.props.indicator.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    } else if (currentCreatedByRef.value !== value.value) {
      commitMutation({
        mutation: indicatorMutationRelationDelete,
        variables: {
          id: this.props.indicator.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      commitMutation({
        mutation: indicatorMutationRelationAdd,
        variables: {
          id: this.props.indicator.id,
          input: {
            fromRole: 'so',
            toId: value.value,
            toRole: 'creator',
            through: 'created_by_ref',
          },
        },
      });
    }
  }

  handleChangeMarkingDefinition(name, values) {
    const { indicator } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(indicator);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: indicatorMutationRelationAdd,
        variables: {
          id: this.props.indicator.id,
          input: {
            fromRole: 'so',
            toId: head(added).value,
            toRole: 'marking',
            through: 'object_marking_refs',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: indicatorMutationRelationDelete,
        variables: {
          id: this.props.indicator.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const { t, indicator, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], indicator) === null
      ? ''
      : {
        label: pathOr(
          null,
          ['createdByRef', 'node', 'name'],
          indicator,
        ),
        value: pathOr(null, ['createdByRef', 'node', 'id'], indicator),
        relation: pathOr(
          null,
          ['createdByRef', 'relation', 'id'],
          indicator,
        ),
      };
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(indicator);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'indicator_pattern',
        'description',
        'valid_from',
        'valid_until',
        'score',
        'createdByRef',
        'killChainPhases',
        'markingDefinitions',
      ]),
    )(indicator);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={indicatorValidation(t)}
          onSubmit={() => true}
          render={({ setFieldValue }) => (
            <div>
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  name="name"
                  component={TextField}
                  label={t('Name')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="name"/>}
                />
                <Field
                  name="indicator_pattern"
                  component={TextField}
                  label={t('Indicator pattern')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="indicator_pattern"/>}
                />
                <Field
                  name="valid_from"
                  component={DatePickerField}
                  label={t('Valid until')}
                  fullWidth={true}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="valid_from"/>}
                />
                <Field
                  name="valid_until"
                  component={DatePickerField}
                  label={t('Valid until')}
                  fullWidth={true}
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="valid_until"/>}
                />
                <Field
                  name="score"
                  component={TextField}
                  label={t('Score')}
                  fullWidth={true}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="score"/>}
                />
                <Field
                  name="description"
                  component={TextField}
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 10 }}
                  onFocus={this.handleChangeFocus.bind(this)}
                  onSubmit={this.handleSubmitField.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="description"/>}
                />
                <Field
                  name="createdByRef"
                  component={AutocompleteCreate}
                  multiple={false}
                  handleCreate={this.handleOpenIdentityCreation.bind(this)}
                  label={t('Author')}
                  options={this.state.identities}
                  onInputChange={this.searchIdentities.bind(this)}
                  onChange={this.handleChangeCreatedByRef.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="createdByRef"/>}
                />
                <Field
                  name="markingDefinitions"
                  component={Autocomplete}
                  multiple={true}
                  label={t('Marking')}
                  options={this.state.markingDefinitions}
                  onInputChange={this.searchMarkingDefinitions.bind(this)}
                  onChange={this.handleChangeMarkingDefinition.bind(this)}
                  onFocus={this.handleChangeFocus.bind(this)}
                  helperText={<SubscriptionFocus context={context} fieldName="markingDefinitions"/>}
                />
              </Form>
              <IdentityCreation
                contextual={true}
                inputValue={this.state.identityInput}
                open={this.state.identityCreation}
                handleClose={this.handleCloseIdentityCreation.bind(this)}
                creationCallback={(data) => {
                  setFieldValue('createdByRef', {
                    label: data.identityAdd.name,
                    value: data.identityAdd.id,
                  });
                  this.handleChangeCreatedByRef('createdByRef', {
                    label: data.identityAdd.name,
                    value: data.identityAdd.id,
                  });
                }}
              />
            </div>
          )}
        />
      </div>
    );
  }
}

IndicatorEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  indicator: PropTypes.object,
  context: PropTypes.array,
};

const IndicatorEditionOverview = createFragmentContainer(
  IndicatorEditionOverviewComponent,
  {
    indicator: graphql`
      fragment IndicatorEditionOverview_indicator on Indicator {
        id
        name
        indicator_pattern
        valid_from
        valid_until
        score
        description
        createdByRef {
          node {
            id
            name
          }
          relation {
            id
          }
        }
        markingDefinitions {
          edges {
            node {
              id
              definition
              definition_type
            }
            relation {
              id
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
)(IndicatorEditionOverview);
