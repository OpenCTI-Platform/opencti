import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form } from 'formik';
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
  filter,
} from 'ramda';
import * as Yup from 'yup';
import { Domain } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import Autocomplete from '../../../../components/Autocomplete';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import {
  commitMutation,
  fetchQuery,
  WS_ACTIVATED,
} from '../../../../relay/environment';
import { now } from '../../../../utils/Time';
import { sectorsSearchQuery } from '../Sectors';
import CreatedByRefField from '../../common/form/CreatedByRefField';
import MarkingDefinitionsField from '../../common/form/MarkingDefinitionsField';

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
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
});

const sectorMutationFieldPatch = graphql`
  mutation SectorEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: EditInput!
  ) {
    sectorEdit(id: $id) {
      fieldPatch(input: $input) {
        ...SectorEditionOverview_sector
      }
    }
  }
`;

export const sectorEditionOverviewFocus = graphql`
  mutation SectorEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    sectorEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const sectorMutationRelationAdd = graphql`
  mutation SectorEditionOverviewRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    sectorEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...SectorEditionOverview_sector
        }
      }
    }
  }
`;

const sectorMutationRelationDelete = graphql`
  mutation SectorEditionOverviewRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    sectorEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        ...SectorEditionOverview_sector
      }
    }
  }
`;

const sectorValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string()
    .min(3, t('The value is too short'))
    .max(5000, t('The value is too long'))
    .required(t('This field is required')),
});

class SectorEditionOverviewComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { subsectors: [] };
  }

  searchSubsector(event) {
    fetchQuery(sectorsSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const subsectors = pipe(
        pathOr([], ['sectors', 'edges']),
        map((n) => ({ label: n.node.name, value: n.node.id })),
      )(data);
      this.setState({
        subsectors: union(
          this.state.subsectors,
          filter((n) => n.value !== this.props.sector.id, subsectors),
        ),
      });
    });
  }

  handleChangeFocus(name) {
    if (WS_ACTIVATED) {
      commitMutation({
        mutation: sectorEditionOverviewFocus,
        variables: {
          id: this.props.sector.id,
          input: {
            focusOn: name,
          },
        },
      });
    }
  }

  handleSubmitField(name, value) {
    sectorValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: sectorMutationFieldPatch,
          variables: { id: this.props.sector.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  handleChangeCreatedByRef(name, value) {
    const { sector } = this.props;
    const currentCreatedByRef = {
      label: pathOr(null, ['createdByRef', 'node', 'name'], sector),
      value: pathOr(null, ['createdByRef', 'node', 'id'], sector),
      relation: pathOr(null, ['createdByRef', 'relation', 'id'], sector),
    };

    if (currentCreatedByRef.value === null) {
      commitMutation({
        mutation: sectorMutationRelationAdd,
        variables: {
          id: this.props.sector.id,
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
        mutation: sectorMutationRelationDelete,
        variables: {
          id: this.props.sector.id,
          relationId: currentCreatedByRef.relation,
        },
      });
      commitMutation({
        mutation: sectorMutationRelationAdd,
        variables: {
          id: this.props.sector.id,
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

  handleChangeMarkingDefinitions(name, values) {
    const { sector } = this.props;
    const currentMarkingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(sector);

    const added = difference(values, currentMarkingDefinitions);
    const removed = difference(currentMarkingDefinitions, values);

    if (added.length > 0) {
      commitMutation({
        mutation: sectorMutationRelationAdd,
        variables: {
          id: this.props.sector.id,
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
        mutation: sectorMutationRelationDelete,
        variables: {
          id: this.props.sector.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  handleChangeSubsectors(name, values) {
    const { sector } = this.props;
    const currentSubsectors = pipe(
      pathOr([], ['subsectors', 'edges']),
      map((n) => ({
        label: n.node.name,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(sector);

    const added = difference(values, currentSubsectors);
    const removed = difference(currentSubsectors, values);

    if (added.length > 0) {
      commitMutation({
        mutation: sectorMutationRelationAdd,
        variables: {
          id: head(added).value,
          input: {
            fromRole: 'part_of',
            toId: this.props.sector.id,
            toRole: 'gather',
            through: 'gathering',
            first_seen: now(),
            last_seen: now(),
            weight: 4,
            stix_id_key: 'create',
          },
        },
      });
    }

    if (removed.length > 0) {
      commitMutation({
        mutation: sectorMutationRelationDelete,
        variables: {
          id: this.props.sector.id,
          relationId: head(removed).relationId,
        },
      });
    }
  }

  render() {
    const {
      t, sector, context, classes,
    } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], sector) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], sector),
        value: pathOr(null, ['createdByRef', 'node', 'id'], sector),
        relation: pathOr(null, ['createdByRef', 'relation', 'id'], sector),
      };
    const subsectors = pipe(
      pathOr([], ['subsectors', 'edges']),
      map((n) => ({
        label: n.node.name,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(sector);
    const markingDefinitions = pipe(
      pathOr([], ['markingDefinitions', 'edges']),
      map((n) => ({
        label: n.node.definition,
        value: n.node.id,
        relationId: n.relation.id,
      })),
    )(sector);
    const initialValues = pipe(
      assoc('createdByRef', createdByRef),
      assoc('subsectors', subsectors),
      assoc('markingDefinitions', markingDefinitions),
      pick([
        'name',
        'description',
        'createdByRef',
        'subsectors',
        'markingDefinitions',
      ]),
    )(sector);
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={sectorValidation(t)}
        onSubmit={() => true}
      >
        {({ setFieldValue }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <TextField
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={this.handleChangeFocus.bind(this)}
              onSubmit={this.handleSubmitField.bind(this)}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <TextField
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
            {!sector.isSubsector ? (
              <Autocomplete
                style={{ marginTop: 20, width: '100%' }}
                name="subsectors"
                multiple={true}
                textfieldprops={{
                  label: t('Subsectors'),
                  helperText: (
                    <SubscriptionFocus
                      context={context}
                      fieldName="subsectors"
                    />
                  ),
                }}
                noOptionsText={t('No available options')}
                options={this.state.subsectors}
                onInputChange={this.searchSubsector.bind(this)}
                onChange={this.handleChangeSubsectors.bind(this)}
                onFocus={this.handleChangeFocus.bind(this)}
                renderOption={(option) => (
                  <React.Fragment>
                    <div className={classes.icon}>
                      <Domain />
                    </div>
                    <div className={classes.text}>{option.label}</div>
                  </React.Fragment>
                )}
              />
            ) : (
              ''
            )}
            <CreatedByRefField
              name="createdByRef"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              helpertext={
                <SubscriptionFocus context={context} fieldName="createdByRef" />
              }
              onChange={this.handleChangeCreatedByRef.bind(this)}
            />
            <MarkingDefinitionsField
              name="markingDefinitions"
              style={{ marginTop: 20, width: '100%' }}
              helpertext={
                <SubscriptionFocus
                  context={context}
                  fieldName="markingDefinitions"
                />
              }
              onChange={this.handleChangeMarkingDefinitions.bind(this)}
            />
          </Form>
        )}
      </Formik>
    );
  }
}

SectorEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  sector: PropTypes.object,
  context: PropTypes.array,
};

const SectorEditionOverview = createFragmentContainer(
  SectorEditionOverviewComponent,
  {
    sector: graphql`
      fragment SectorEditionOverview_sector on Sector {
        id
        name
        description
        isSubsector
        createdByRef {
          node {
            id
            name
            entity_type
          }
          relation {
            id
          }
        }
        subsectors {
          edges {
            node {
              id
              name
            }
            relation {
              id
            }
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
)(SectorEditionOverview);
