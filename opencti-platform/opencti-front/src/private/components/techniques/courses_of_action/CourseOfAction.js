import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import CourseOfActionHeader from './CourseOfActionHeader';
import CourseOfActionOverview from './CourseOfActionOverview';
import CourseOfActionDetails from './CourseOfActionDetails';
import CourseOfActionEdition from './CourseOfActionEdition';
import EntityExternalReferences from '../../common/external_references/EntityExternalReferences';
import EntityStixRelationsPie from '../../common/stix_relations/EntityStixRelationsPie';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityStixRelationsChart from '../../common/stix_relations/EntityStixRelationsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class CourseOfActionComponent extends Component {
  render() {
    const { classes, courseOfAction } = this.props;
    return (
      <div className={classes.container}>
        <CourseOfActionHeader courseOfAction={courseOfAction} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={4}>
            <CourseOfActionOverview courseOfAction={courseOfAction} />
          </Grid>
          <Grid item={true} xs={4}>
            <CourseOfActionDetails courseOfAction={courseOfAction} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityExternalReferences entityId={courseOfAction.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 30 }}
        >
          <Grid item={true} xs={4}>
            <EntityStixRelationsChart
              entityId={courseOfAction.id}
              relationType="uses"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixRelationsPie
              entityId={courseOfAction.id}
              entityType="Stix-Domain-Entity"
              field="entity_type"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={courseOfAction.id} />
          </Grid>
        </Grid>
        <CourseOfActionEdition courseOfActionId={courseOfAction.id} />
      </div>
    );
  }
}

CourseOfActionComponent.propTypes = {
  courseOfAction: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CourseOfAction = createFragmentContainer(CourseOfActionComponent, {
  courseOfAction: graphql`
    fragment CourseOfAction_courseOfAction on CourseOfAction {
      id
      ...CourseOfActionHeader_courseOfAction
      ...CourseOfActionOverview_courseOfAction
      ...CourseOfActionDetails_courseOfAction
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(CourseOfAction);
