import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import CourseOfActionOverview from './CourseOfActionOverview';
import CourseOfActionDetails from './CourseOfActionDetails';
import CourseOfActionEdition from './CourseOfActionEdition';
import CourseOfActionPopover from './CourseOfActionPopover';
import EntityExternalReferences from '../../common/external_references/EntityExternalReferences';
import EntityStixRelationsPie from '../../common/stix_relations/EntityStixRelationsPie';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityStixRelationsChart from '../../common/stix_relations/EntityStixRelationsChart';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixObjectNotes from '../../common/stix_object/StixObjectNotes';

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
        <StixDomainEntityHeader
          stixDomainEntity={courseOfAction}
          PopoverComponent={<CourseOfActionPopover />}
        />
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
        <StixObjectNotes entityId={courseOfAction.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
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
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CourseOfActionEdition courseOfActionId={courseOfAction.id} />
        </Security>
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
      name
      alias
      ...CourseOfActionOverview_courseOfAction
      ...CourseOfActionDetails_courseOfAction
    }
  `,
});

export default compose(inject18n, withStyles(styles))(CourseOfAction);
