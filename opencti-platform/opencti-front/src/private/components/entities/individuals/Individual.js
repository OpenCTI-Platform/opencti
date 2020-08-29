import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, dissoc, isNil, propOr,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import IndividualOverview from './IndividualOverview';
import IndividualDetails from './IndividualDetails';
import IndividualEdition from './IndividualEdition';
import IndividualPopover from './IndividualPopover';
import EntityLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import EntityCampaignsChart from '../../threats/campaigns/EntityCampaignsChart';
import EntityReportsChart from '../../analysis/reports/StixCoreObjectReportsChart';
import EntityXOpenCTIIncidentsChart from '../../events/x_opencti_incidents/EntityXOpenCTIIncidentsChart';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class IndividualComponent extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-individual-${props.individual.id}`,
    );
    this.state = {
      viewAs: propOr('knowledge', 'viewAs', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-individual-${this.props.individual.id}`,
      dissoc('filters', this.state),
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const { classes, individual } = this.props;
    const { viewAs } = this.state;
    if (viewAs === 'author') {
      return (
        <div className={classes.container}>
          <StixDomainObjectHeader
            stixDomainObject={individual}
            PopoverComponent={<IndividualPopover />}
            onViewAs={this.handleChangeViewAs.bind(this)}
            viewAs={this.state.viewAs}
          />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
          >
            <Grid item={true} xs={3}>
              <IndividualOverview individual={individual} />
            </Grid>
            <Grid item={true} xs={3}>
              <IndividualDetails individual={individual} />
            </Grid>
            <Grid item={true} xs={6}>
              <EntityLastReports authorId={individual.id} />
            </Grid>
          </Grid>
          <StixCoreObjectNotes stixCoreObjectId={individual.id} />
          <Grid
            container={true}
            spacing={3}
            classes={{ container: classes.gridContainer }}
            style={{ marginTop: 15 }}
          >
            <Grid item={true} xs={12}>
              <EntityReportsChart authorId={individual.id} />
            </Grid>
          </Grid>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <IndividualEdition individualId={individual.id} />
          </Security>
        </div>
      );
    }
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={individual}
          PopoverComponent={<IndividualPopover />}
          onViewAs={this.handleChangeViewAs.bind(this)}
          viewAs={this.state.viewAs}
          disablePopover={!isNil(individual.external)}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <IndividualOverview individual={individual} />
          </Grid>
          <Grid item={true} xs={3}>
            <IndividualDetails individual={individual} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={individual.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes stixCoreObjectId={individual.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={4}>
            <EntityCampaignsChart entityId={individual.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityXOpenCTIIncidentsChart entityId={individual.id} />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={individual.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IndividualEdition individualId={individual.id} />
        </Security>
      </div>
    );
  }
}

IndividualComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Individual = createFragmentContainer(IndividualComponent, {
  individual: graphql`
    fragment Individual_individual on Individual {
      id
      name
      x_opencti_aliases
      ...IndividualOverview_individual
      ...IndividualDetails_individual
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Individual);
