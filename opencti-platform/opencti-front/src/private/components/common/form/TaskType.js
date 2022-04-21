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

const TaskTypeQuery = graphql`
  query TaskTypeQuery {
    __type(name: "TaskType") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

const TaskTypeRelatedTaskQuery = graphql`
  query TaskTypeRelatedTaskQuery($orderedBy: OscalTaskOrdering, $orderMode: OrderingMode) {
    oscalTasks(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          name
          description
        }
      }
    }
  }
`;

const TaskTypeAssociatedActivitiesQuery = graphql`
  query TaskTypeAssociatedActivitiesQuery($orderedBy: AssociatedActivityOrdering, $orderMode: OrderingMode) {
    associatedActivities(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          id
          activity_id {
            name
            description
          }
        }
      }
    }
  }
`;

const TaskTypeResponsiblePartiesQuery = graphql`
  query TaskTypeResponsiblePartiesQuery($orderedBy: OscalResponsiblePartyOrdering, $orderMode: OrderingMode) {
    oscalResponsibleParties(orderedBy: $orderedBy, orderMode: $orderMode) {
      edges {
        node {
          parties {
            name
            description
          }
        }
      }
    }
  }
`;

const TaskTypeDependenciesQuery = graphql`
  query TaskTypeDependenciesQuery {
    oscalTasks {
      edges {
        node {
          name
          description
        }
      }
    }
  }
`;

class TaskType extends Component {
  constructor(props) {
    super(props);
    this.state = {
      TaskTypeList: []
    };
  }

  componentDidUpdate(prevProps) {
    if (this.props.name !== prevProps.name) {
      this.handleRelatedTaskField();
    }
  }

  componentDidMount() {
   this.handleRelatedTaskField();
  }

  handleRelatedTaskField(){
    if(this.props.name === "task_type"){
      fetchDarklightQuery(TaskTypeQuery)
      .toPromise()
      .then((data) => {
        const TaskTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          TaskTypeList: {
            ...this.state.entities,
            TaskTypeEntities,
          },
        });
      });
    }
    if(this.props.name === "related_tasks"){
      fetchDarklightQuery(TaskTypeRelatedTaskQuery, {
        orderedBy: 'name',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const TaskTypeEntities = R.pipe(
          R.pathOr([], ['oscalTasks', 'edges']),
          R.map((n) => ({
            label: n.node.description,
            value: n.node.name,
          }))
        )(data);
        this.setState({
          TaskTypeList: {
            ...this.state.entities,
            TaskTypeEntities,
          },
        });
      });
    }
    if(this.props.name === "associated_activities"){
      fetchDarklightQuery(TaskTypeAssociatedActivitiesQuery, {
        orderedBy: 'activity_id',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const TaskTypeEntities = R.pipe(
          R.pathOr([], ['associatedActivities', 'edges']),
          R.map((n) => ({
            label: n.node.activity_id.description,
            value: n.node.activity_id.name,
          }))
        )(data);
        this.setState({
          TaskTypeList: {
            ...this.state.entities,
            TaskTypeEntities,
          },
        });
      });
    }
    if(this.props.name === "responsible_roles"){
      fetchDarklightQuery(TaskTypeResponsiblePartiesQuery, {
        orderedBy: 'labels',
        orderMode: 'asc',
      })
      .toPromise()
      .then((data) => {
        const TaskTypeEntities = R.pipe(
          R.pathOr([], ['oscalResponsibleParties', 'edges']),
          R.map((n) => ({
            label: n.node.parties.description,
            value: n.node.parties.name,
          }))
        )(data);
        this.setState({
          TaskTypeList: {
            ...this.state.entities,
            TaskTypeEntities,
          },
        });
      });
    }
    if(this.props.name === "task_dependencies"){
      fetchDarklightQuery(TaskTypeDependenciesQuery)
      .toPromise()
      .then((data) => {
        const TaskTypeEntities = R.pipe(
          R.pathOr([], ['oscalTasks', 'edges']),
          R.map((n) => ({
            label: n.node.description,
            value: n.node.name,
          }))
        )(data);
        this.setState({
          TaskTypeList: {
            ...this.state.entities,
            TaskTypeEntities,
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
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const TaskTypeList = R.pathOr(
      [],
      ['TaskTypeEntities'],
      this.state.TaskTypeList
    );
    return (
      <div>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {TaskTypeList.map(
            (et, key) =>
              et.value && (
                <MenuItem key={key} value={et.value}>{et.value}</MenuItem>
              )
          )}
        </Field>
      </div>
    );
  }
}

export default inject18n(TaskType);
