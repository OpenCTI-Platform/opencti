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
import EntityExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import EntityStixCoreRelationshipsPie from '../../common/stix_core_relationships/EntityStixCoreRelationshipsPie';
import EntityReportsChart from '../../analysis/reports/EntityReportsChart';
import EntityStixCoreRelationshipsChart from '../../common/stix_core_relationships/EntityStixCoreRelationshipsChart';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../analysis/notes/StixCoreObjectNotes';

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
        <StixDomainObjectHeader
          stixDomainObject={courseOfAction}
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
        <StixCoreObjectNotes entityId={courseOfAction.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityStixCoreRelationshipsChart
              entityId={courseOfAction.id}
              relationshipType="uses"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixCoreRelationshipsPie
              entityId={courseOfAction.id}
              entityType="Stix-Domain-Object"
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
      x_opencti_aliases
      ...CourseOfActionOverview_courseOfAction
      ...CourseOfActionDetails_courseOfAction
    }
  `,
});

export default compose(inject18n, withStyles(styles))(CourseOfAction);
