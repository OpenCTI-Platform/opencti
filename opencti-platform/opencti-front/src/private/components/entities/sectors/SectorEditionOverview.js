import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import {
  assoc,
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
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import {
  commitMutation,
  fetchQuery,
} from '../../../../relay/environment';
import { now } from '../../../../utils/Time';
import { sectorsSearchQuery } from '../Sectors';
import CreatedByRefField from '../../common/form/CreatedByRefField';
import MarkingDefinitionsField from '../../common/form/MarkingDefinitionsField';

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
    this.state = { subSectors: [] };
  }

  searchSubsector(event) {
    fetchQuery(sectorsSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    }).then((data) => {
      const subSectors = pipe(
        pathOr([], ['sectors', 'edges']),
        map((n) => ({ label: n.node.name, value: n.node.id })),
      )(data);
      this.setState({
        subSectors: union(
          this.state.subSectors,
          filter((n) => n.value !== this.props.sector.id, subSectors),
        ),
      });
    });
  }

  handleChangeFocus(name) {
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
      if (value.value) {
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
      pathOr([], ['subSectors', 'edges']),
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
    const { t, sector, context } = this.props;
    const createdByRef = pathOr(null, ['createdByRef', 'node', 'name'], sector) === null
      ? ''
      : {
        label: pathOr(null, ['createdByRef', 'node', 'name'], sector),
        value: pathOr(null, ['createdByRef', 'node', 'id'], sector),
        relation: pathOr(null, ['createdByRef', 'relation', 'id'], sector),
      };
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
      assoc('markingDefinitions', markingDefinitions),
      pick(['name', 'description', 'createdByRef', 'markingDefinitions']),
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
              component={TextField}
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
        isSubSector
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

export default inject18n(SectorEditionOverview);
