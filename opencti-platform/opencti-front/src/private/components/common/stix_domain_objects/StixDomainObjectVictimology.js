import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Drawer from '@mui/material/Drawer';
import {
  DomainOutlined,
  LocalPlayOutlined,
  GroupOutlined,
} from '@mui/icons-material';
import Loader from '../../../../components/Loader';
import StixDomainObjectVictimologySectors, {
  stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery,
} from './StixDomainObjectVictimologySectors';
import StixDomainObjectVictimologyRegions, {
  stixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery,
} from './StixDomainObjectVictimologyRegions';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import EntityStixCoreRelationships from '../stix_core_relationships/EntityStixCoreRelationships';

const styles = (theme) => ({
  container: {
    marginTop: 15,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '0 200px 0 205px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    height: 50,
  },
});

class StixDomainObjectVictimology extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-victimology-${props.stixDomainObjectId}`,
    );
    this.state = {
      searchTerm: propOr('', 'searchTerm', params),
      type: propOr('sectors', 'type', params),
      viewMode: propOr('map', 'viewMode', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-victimology-${this.props.stixDomainObjectId}`,
      this.state,
    );
  }

  handleChangeType(type) {
    this.setState({ type }, () => this.saveView());
  }

  handleChangeView(viewMode) {
    this.setState({ viewMode }, () => this.saveView());
  }

  render() {
    const { type, viewMode } = this.state;
    const {
      classes, stixDomainObjectId, entityLink, t,
    } = this.props;
    let types = ['Sector', 'Organization'];
    if (type === 'regions') {
      types = ['Region', 'Country', 'City'];
    } else if (type === 'individuals') {
      types = ['Individual'];
    }
    const paginationOptions = {
      fromId: stixDomainObjectId,
      toTypes: types,
      relationship_type: 'targets',
    };
    return (
      <div className={classes.container} id="container">
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
        >
          <Grid container={true} spacing={1}>
            <Grid item={true} xs="auto">
              <Tooltip title={t('Sectors and organizations')}>
                <IconButton
                  color={type === 'sectors' ? 'secondary' : 'primary'}
                  onClick={this.handleChangeType.bind(this, 'sectors')}
                  size="large">
                  <DomainOutlined />
                </IconButton>
              </Tooltip>
            </Grid>
            <Grid item={true} xs="auto">
              <Tooltip title={t('Regions, countries and cities')}>
                <IconButton
                  color={type === 'regions' ? 'secondary' : 'primary'}
                  onClick={this.handleChangeType.bind(this, 'regions')}
                  size="large">
                  <LocalPlayOutlined />
                </IconButton>
              </Tooltip>
            </Grid>
            <Grid item={true} xs="auto">
              <Tooltip title={t('Individuals')}>
                <IconButton
                  color={type === 'individuals' ? 'secondary' : 'primary'}
                  onClick={this.handleChangeType.bind(this, 'individuals')}
                  size="large">
                  <GroupOutlined />
                </IconButton>
              </Tooltip>
            </Grid>
          </Grid>
        </Drawer>
        {type === 'sectors' && (
          <QueryRenderer
            query={stixDomainObjectVictimologySectorsStixCoreRelationshipsQuery}
            variables={{ first: 500, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainObjectVictimologySectors
                    data={props}
                    entityLink={entityLink}
                    paginationOptions={paginationOptions}
                    stixDomainObjectId={stixDomainObjectId}
                  />
                );
              }
              return <Loader withRightPadding={true} />;
            }}
          />
        )}
        {type === 'regions' ? (
          <QueryRenderer
            query={stixDomainObjectVictimologyRegionsStixCoreRelationshipsQuery}
            variables={{ first: 500, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainObjectVictimologyRegions
                    data={props}
                    entityLink={entityLink}
                    paginationOptions={paginationOptions}
                    stixDomainObjectId={stixDomainObjectId}
                    handleChangeView={this.handleChangeView.bind(this)}
                    currentView={viewMode}
                  />
                );
              }
              return <Loader withRightPadding={true} />;
            }}
          />
        ) : (
          ''
        )}
        {type === 'individuals' && (
          <EntityStixCoreRelationships
            entityLink={entityLink}
            entityId={stixDomainObjectId}
            targetStixDomainObjectTypes={types}
            relationshipTypes={['targets']}
            noBottomBar={true}
            isRelationReversed={false}
            noState={true}
          />
        )}
      </div>
    );
  }
}

StixDomainObjectVictimology.propTypes = {
  stixDomainObjectId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectVictimology);
