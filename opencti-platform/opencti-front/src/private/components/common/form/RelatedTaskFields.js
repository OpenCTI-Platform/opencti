/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import { Information } from 'mdi-material-ui';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const RelatedTaskFieldsRelatedTaskQuery = graphql`
  query RelatedTaskFieldsRelatedTaskQuery($orderedBy: OscalTaskOrdering, $orderMode: OrderingMode) {
    oscalTasks(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const RelatedTaskFieldsAssociatedActivitiesQuery = graphql`
  query RelatedTaskFieldsAssociatedActivitiesQuery($orderedBy: AssociatedActivityOrdering, $orderMode: OrderingMode) {
    associatedActivities(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          activity_id {
            id
            name
            description
          }
        }
      }
    }
  }
`;

const RelatedTaskFieldsResponsiblePartiesQuery = graphql`
  query RelatedTaskFieldsResponsiblePartiesQuery($orderedBy: OscalResponsiblePartyOrdering, $orderMode: OrderingMode) {
    oscalResponsibleParties(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const RelatedTaskFieldsDependenciesQuery = graphql`
  query RelatedTaskFieldsDependenciesQuery($orderedBy: OscalTaskOrdering, $orderMode: OrderingMode) {
    oscalTasks(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

class RelatedTaskFields extends Component {
  constructor(props) {
    super(props);
    this.state = {
      RelatedTaskFieldsList: []
    };
  }

  // componentDidUpdate(prevProps) {
  //   if (this.props.name !== prevProps.name) {
  //     this.handleRelatedTaskField();
  //   }
  // }

  componentDidMount() {
   this.handleRelatedTaskField();
  }

  handleRelatedTaskField(){
    if(this.props.name === "related_tasks"){
      fetchDarklightQuery(RelatedTaskFieldsRelatedTaskQuery, {
        orderedBy: 'name',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const RelatedTaskFieldsEntities = R.pipe(
          R.pathOr([], ['oscalTasks', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            label: n.node.description,
            value: n.node.name,
          }))
        )(data);
        this.setState({
          RelatedTaskFieldsList: {
            ...this.state.entities,
            RelatedTaskFieldsEntities,
          },
        });
      });
    }
    if(this.props.name === "associated_activities"){
      fetchDarklightQuery(RelatedTaskFieldsAssociatedActivitiesQuery, {
        orderedBy: 'activity_id',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const RelatedTaskFieldsEntities = R.pipe(
          R.pathOr([], ['associatedActivities', 'edges']),
          R.map((n) => ({
            id: n.node.activity_id.id,
            label: n.node.activity_id.description,
            value: n.node.activity_id.name,
          }))
        )(data);
        this.setState({
          RelatedTaskFieldsList: {
            ...this.state.entities,
            RelatedTaskFieldsEntities,
          },
        });
      });
    }
    if(this.props.name === "responsible_roles"){
      fetchDarklightQuery(RelatedTaskFieldsResponsiblePartiesQuery, {
        orderedBy: 'name',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const RelatedTaskFieldsEntities = R.pipe(
          R.pathOr([], ['oscalResponsibleParties', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            label: n.node.description,
            value: n.node.name,
          })),
        )(data);
        this.setState({
          RelatedTaskFieldsList: {
            ...this.state.entities,
            RelatedTaskFieldsEntities,
          },
        });
      });
    }
    if(this.props.name === "task_dependencies"){
      fetchDarklightQuery(RelatedTaskFieldsDependenciesQuery, {
        orderedBy: 'name',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const RelatedTaskFieldsEntities = R.pipe(
          R.pathOr([], ['oscalTasks', 'edges']),
          R.map((n) => ({
            id: n.node.id,
            label: n.node.description,
            value: n.node.name,
          }))
        )(data);
        this.setState({
          RelatedTaskFieldsList: {
            ...this.state.entities,
            RelatedTaskFieldsEntities,
          },
        });
      });
    }
  }

  render() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      onChange,
      multiple,
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const RelatedTaskFieldsList = R.pathOr(
      [],
      ['RelatedTaskFieldsEntities'],
      this.state.RelatedTaskFieldsList
    );
    return (
      <div>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          multiple={multiple}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {RelatedTaskFieldsList.map(
            (et, key) =>
              et.id && (
                <MenuItem key={key} value={et.id}>{et.value}</MenuItem>
              )
          )}
        </Field>
      </div>
    );
  }
}

export default inject18n(RelatedTaskFields);
