import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import IntrusionSetOverview from './IntrusionSetOverview';
import IntrusionSetDetails from './IntrusionSetDetails';
import IntrusionSetEdition from './IntrusionSetEdition';
import IntrusionSetPopover from './IntrusionSetPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityCampaignsChart from '../campaigns/EntityCampaignsChart';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../common/stix_core_object/StixCoreObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class IntrusionSetComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={intrusionSet}
          PopoverComponent={<IntrusionSetPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <IntrusionSetOverview intrusionSet={intrusionSet} />
          </Grid>
          <Grid item={true} xs={3}>
            <IntrusionSetDetails intrusionSet={intrusionSet} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={intrusionSet.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={intrusionSet.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart
              entityId={intrusionSet.id}
              relationship_type="attributed-to"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixCoreRelationshipsDonut
              entityId={intrusionSet.id}
              entityType="Indicator"
              relationship_type="indicates"
              field="x_opencti_main_observable_type"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={intrusionSet.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IntrusionSetEdition intrusionSetId={intrusionSet.id} />
        </Security>
      </div>
    );
  }
}

IntrusionSetComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const IntrusionSet = createFragmentContainer(IntrusionSetComponent, {
  intrusionSet: graphql`
    fragment IntrusionSet_intrusionSet on IntrusionSet {
      id
      name
      aliases
      ...IntrusionSetOverview_intrusionSet
      ...IntrusionSetDetails_intrusionSet
    }
  `,
});

export default compose(inject18n, withStyles(styles))(IntrusionSet);
