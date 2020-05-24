import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import IconButton from '@material-ui/core/IconButton';
import Tooltip from '@material-ui/core/Tooltip';
import Drawer from '@material-ui/core/Drawer';
import { DomainOutlined, MapOutlined, GroupOutlined } from '@material-ui/icons';
import Loader from '../../../../components/Loader';
import StixDomainEntityVictimologySectors, {
  stixDomainEntityVictimologySectorsStixRelationsQuery,
} from './StixDomainEntityVictimologySectors';
import StixDomainEntityVictimologyRegions, {
  stixDomainEntityVictimologyRegionsStixRelationsQuery,
} from './StixDomainEntityVictimologyRegions';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import {
  buildViewParamsFromUrlAndStorage,
  saveViewParameters,
} from '../../../../utils/ListParameters';
import EntityStixRelations from '../stix_relations/EntityStixRelations';

const styles = (theme) => ({
  container: {
    marginTop: 15,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 70px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
});

class StixDomainEntityVictimology extends Component {
  constructor(props) {
    super(props);
    const params = buildViewParamsFromUrlAndStorage(
      props.history,
      props.location,
      `view-victimology-${props.stixDomainEntityId}`,
    );
    this.state = {
      inferred: propOr(false, 'inferred', params),
      searchTerm: propOr('', 'searchTerm', params),
      type: propOr('sectors', 'type', params),
    };
  }

  saveView() {
    saveViewParameters(
      this.props.history,
      this.props.location,
      `view-victimology-${this.props.stixDomainEntityId}`,
      this.state,
    );
  }

  handleChangeType(type) {
    this.setState({ type }, () => this.saveView());
  }

  handleChangeInferred() {
    this.setState(
      {
        inferred: !this.state.inferred,
      },
      () => this.saveView(),
    );
  }

  handleSearch(value) {
    this.setState({ searchTerm: value }, () => this.saveView());
  }

  render() {
    const { inferred, searchTerm, type } = this.state;
    const {
      classes, stixDomainEntityId, entityLink, t,
    } = this.props;
    let types = ['Sector', 'Organization'];
    if (type === 'regions') {
      types = ['Region', 'Country', 'City'];
    } else if (type === 'persons') {
      types = ['User'];
    }
    const paginationOptions = {
      fromId: stixDomainEntityId,
      toTypes: types,
      relationType: 'targets',
      inferred,
      search: searchTerm,
    };
    return (
      <div className={classes.container}>
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
                >
                  <DomainOutlined />
                </IconButton>
              </Tooltip>
            </Grid>
            <Grid item={true} xs="auto">
              <Tooltip title={t('Regions, countries and cities')}>
                <IconButton
                  color={type === 'regions' ? 'secondary' : 'primary'}
                  onClick={this.handleChangeType.bind(this, 'regions')}
                >
                  <MapOutlined />
                </IconButton>
              </Tooltip>
            </Grid>
            <Grid item={true} xs="auto">
              <Tooltip title={t('Persons')}>
                <IconButton
                  color={type === 'persons' ? 'secondary' : 'primary'}
                  onClick={this.handleChangeType.bind(this, 'persons')}
                >
                  <GroupOutlined />
                </IconButton>
              </Tooltip>
            </Grid>
            <Grid item={true} xs="auto">
              <FormControlLabel
                style={{ paddingTop: 5, marginLeft: 0 }}
                control={
                  <Switch
                    checked={inferred}
                    onChange={this.handleChangeInferred.bind(this)}
                    color="primary"
                  />
                }
                label={t('Inferences')}
              />
            </Grid>
          </Grid>
        </Drawer>
        {type === 'sectors' ? (
          <QueryRenderer
            query={stixDomainEntityVictimologySectorsStixRelationsQuery}
            variables={{ first: 500, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainEntityVictimologySectors
                    data={props}
                    entityLink={entityLink}
                    handleSearch={this.handleSearch.bind(this)}
                    paginationOptions={paginationOptions}
                    stixDomainEntityId={stixDomainEntityId}
                  />
                );
              }
              return <Loader withRightPadding={true} />;
            }}
          />
        ) : (
          ''
        )}
        {type === 'regions' ? (
          <QueryRenderer
            query={stixDomainEntityVictimologyRegionsStixRelationsQuery}
            variables={{ first: 500, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainEntityVictimologyRegions
                    data={props}
                    entityLink={entityLink}
                    handleSearch={this.handleSearch.bind(this)}
                    paginationOptions={paginationOptions}
                    stixDomainEntityId={stixDomainEntityId}
                  />
                );
              }
              return <Loader withRightPadding={true} />;
            }}
          />
        ) : (
          ''
        )}
        {type === 'persons' ? (
          <EntityStixRelations
            entityId={stixDomainEntityId}
            targetEntityTypes={types}
            relationType="targets"
            noBottomBar={true}
            creationIsFrom={true}
            inference={inferred}
          />
        ) : (
          ''
        )}
      </div>
    );
  }
}

StixDomainEntityVictimology.propTypes = {
  stixDomainEntityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityVictimology);
