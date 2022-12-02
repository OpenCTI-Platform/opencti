/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Redirect } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../../components/i18n';
import EntityTaskDetails from './EntityTaskDetails';
import EntitiesTasksPopover from './EntitiesTasksPopover';
import EntitiesTasksDeletion from './EntitiesTasksDeletion';
import CyioDomainObjectHeader from '../../../common/stix_domain_objects/CyioDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import CyioCoreObjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import TaskEntityEditionContainer from './TaskEntityEditionContainer';
import EntitiesTasksCreation from './EntitiesTasksCreation';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class EntityTaskComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      openDataCreation: false,
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.setState({ openDataCreation: !this.state.openDataCreation });
  }

  render() {
    const {
      classes,
      task,
      history,
      refreshQuery,
      location,
    } = this.props;
    return (
      <>
        <div className={classes.container}>
          <CyioDomainObjectHeader
            name={task.name}
            history={history}
            cyioDomainObject={task}
            goBack='/data/entities/tasks'
            PopoverComponent={<EntitiesTasksPopover />}
            OperationsComponent={<EntitiesTasksDeletion />}
            handleDisplayEdit={this.handleDisplayEdit.bind(this)}
            handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={12}>
              <EntityTaskDetails task={task} history={history} refreshQuery={refreshQuery} />
            </Grid>
          </Grid>
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 25 }}
          >
            <Grid item={true} xs={6}>
              <CyioCoreObjectExternalReferences
                typename={task.__typename}
                externalReferences={task.links}
                fieldName='links'
                cyioCoreObjectId={task?.id}
                refreshQuery={refreshQuery}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <CyioCoreObjectOrCyioCoreRelationshipNotes
                typename={task.__typename}
                notes={task.remarks}
                refreshQuery={refreshQuery}
                fieldName='remarks'
                marginTop='0px'
                cyioCoreObjectOrCyioCoreRelationshipId={task?.id}
              />
            </Grid>
          </Grid>
        </div>
        <EntitiesTasksCreation
          openDataCreation={this.state.openDataCreation}
          handleTaskCreation={this.handleOpenNewCreation.bind(this)}
          history={history}
          task={task}
        />
        <TaskEntityEditionContainer
          displayEdit={this.state.displayEdit}
          history={history}
          task={task}
          refreshQuery={refreshQuery}
          handleDisplayEdit={this.handleDisplayEdit.bind(this)}
        />
      </>
    );
  }
}

EntityTaskComponent.propTypes = {
  task: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const EntityTask = createFragmentContainer(EntityTaskComponent, {
  task: graphql`
    fragment EntityTask_task on OscalTask {
      __typename
      id
      created
      modified
      name
      description
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      links {
        __typename
        id
        source_name
        description
        entity_type
        url
        hashes {
          value
        }
        external_id
      }
      remarks {
        __typename
        id
        entity_type
        abstract
        content
        authors
      }
      ...EntityTaskDetails_task
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EntityTask);
