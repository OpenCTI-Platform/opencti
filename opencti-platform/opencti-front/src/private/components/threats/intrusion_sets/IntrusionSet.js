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
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import EntityStixRelationsDonut from '../../common/stix_relations/EntityStixRelationsDonut';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityCampaignsChart from '../campaigns/EntityCampaignsChart';
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

class IntrusionSetComponent extends Component {
  render() {
    const { classes, intrusionSet } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainEntityHeader
          stixDomainEntity={intrusionSet}
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
        <StixObjectNotes entityId={intrusionSet.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart
              entityId={intrusionSet.id}
              relationType="attributed-to"
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixRelationsDonut
              entityId={intrusionSet.id}
              entityType="Indicator"
              relationType="indicates"
              field="main_observable_type"
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
      alias
      ...IntrusionSetOverview_intrusionSet
      ...IntrusionSetDetails_intrusionSet
    }
  `,
});

export default compose(inject18n, withStyles(styles))(IntrusionSet);
