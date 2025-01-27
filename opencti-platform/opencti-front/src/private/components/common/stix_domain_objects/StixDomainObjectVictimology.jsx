import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import Divider from '@mui/material/Divider';
import StixDomainObjectVictimologySectors, { stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery } from './StixDomainObjectVictimologySectors';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import EntityStixCoreRelationships from '../stix_core_relationships/EntityStixCoreRelationships';
import EntityStixCoreRelationshipsHorizontalBars from '../stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import StixDomainObjectVictimologyMap from './StixDomainObjectVictimologyMap';

const styles = (theme) => ({
  container: {
    marginTop: 40,
  },
  bottomNav: {
    zIndex: 1,
    padding: '0 200px 0 205px',
    display: 'flex',
    height: 50,
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: 0,
    overflow: 'hidden',
  },
});

class StixDomainObjectVictimology extends Component {
  constructor(props) {
    super(props);
    this.state = {
      viewMode: 'relationships',
    };
  }

  handleChangeView(viewMode) {
    this.setState({ viewMode });
  }

  render() {
    const { viewMode } = this.state;
    const {
      classes,
      stixDomainObjectId,
      entityLink,
      t,
      defaultStartTime,
      defaultStopTime,
    } = this.props;
    const paginationOptionsSectors = {
      fromId: stixDomainObjectId,
      toTypes: ['Sector', 'Organization', 'Individual'],
      relationship_type: 'targets',
    };
    return (
      <>
        <Grid container={true} spacing={3} style={{ marginTop: 15 }}>
          <Grid
            item
            xs={6}
            style={{ height: 300, minHeight: 300, paddingTop: 0 }}
          >
            <EntityStixCoreRelationshipsHorizontalBars
              title={t('Victimology (sectors)')}
              fromId={stixDomainObjectId}
              toTypes={['Sector']}
              relationshipType="targets"
              field="internal_id"
              isTo={true}
            />
          </Grid>
          <Grid
            item
            xs={6}
            style={{ height: 300, minHeight: 300, paddingTop: 0 }}
          >
            <EntityStixCoreRelationshipsHorizontalBars
              title={t('Victimology (regions)')}
              fromId={stixDomainObjectId}
              toTypes={['Region']}
              relationshipType="targets"
              field="internal_id"
              isTo={true}
            />
          </Grid>
          <Grid
            item
            xs={6}
            style={{
              marginTop: 60,
              height: 300,
              minHeight: 300,
              paddingTop: 0,
            }}
          >
            <EntityStixCoreRelationshipsHorizontalBars
              title={t('Victimology (countries)')}
              fromId={stixDomainObjectId}
              toTypes={['Country']}
              relationshipType="targets"
              field="internal_id"
              isTo={true}
            />
          </Grid>
          <Grid
            item
            xs={6}
            style={{
              marginTop: 60,
              height: 300,
              minHeight: 300,
              paddingTop: 0,
            }}
          >
            <StixDomainObjectVictimologyMap
              title={t('Victimology (countries)')}
              stixDomainObjectId={stixDomainObjectId}
            />
          </Grid>
        </Grid>
        <Divider style={{ marginTop: 50 }} />
        <div className={classes.container} id="container">
          {(viewMode === 'entities' || viewMode === 'relationships') && (
            <EntityStixCoreRelationships
              entityLink={entityLink}
              entityId={stixDomainObjectId}
              stixCoreObjectTypes={[
                'System',
                'Individual',
                'Organization',
                'Sector',
                'City',
                'Country',
                'Region',
                'Position',
                'Event',
                'Administrative-Area',
              ]}
              relationshipTypes={['targets']}
              isRelationReversed={false}
              enableExport={true}
              currentView={viewMode}
              handleChangeView={this.handleChangeView.bind(this)}
              enableNestedView={true}
              enableEntitiesView={false}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
            />
          )}
          {viewMode === 'nested' && (
          <QueryRenderer
            query={
              stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery
            }
            variables={{ first: 500, ...paginationOptionsSectors }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainObjectVictimologySectors
                    data={props}
                    entityLink={entityLink}
                    paginationOptions={paginationOptionsSectors}
                    stixDomainObjectId={stixDomainObjectId}
                    handleChangeView={this.handleChangeView.bind(this)}
                  />
                );
              }
              return <div />;
            }}
          />
          )}
        </div>
      </>
    );
  }
}

StixDomainObjectVictimology.propTypes = {
  stixDomainObjectId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimology);
