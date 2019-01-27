import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import SectorHeader from './SectorHeader';
import SectorOverview from './SectorOverview';
import SectorEdition from './SectorEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityObservablesChart from '../observable/EntityObservablesChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityKillChainPhasesChart from '../kill_chain_phase/EntityKillChainPhasesChart';
import { requestSubscription } from '../../../relay/environment';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const subscription = graphql`
    subscription SectorSubscription($id: ID!) {
        stixDomainEntity(id: $id) {
            ...on Sector {
                ...Sector_sector   
            }
        }
    }
`;

class SectorComponent extends Component {
  componentDidMount() {
    const sub = requestSubscription({
      subscription,
      variables: {
        id: this.props.sector.id,
      },
    });
    this.setState({
      sub,
    });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const { classes, sector } = this.props;
    return (
      <div className={classes.container}>
        <SectorHeader sector={sector}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <SectorOverview sector={sector}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={sector.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <EntityObservablesChart sector={sector}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart sector={sector}/>
          </Grid>
          <Grid item={true} xs={4}>
            <EntityKillChainPhasesChart sector={sector}/>
          </Grid>
        </Grid>
        <SectorEdition sectorId={sector.id}/>
      </div>
    );
  }
}

SectorComponent.propTypes = {
  sector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Sector = createFragmentContainer(SectorComponent, {
  sector: graphql`
      fragment Sector_sector on Sector {
          id
          ...SectorHeader_sector
          ...SectorOverview_sector
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Sector);
