import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import { withStyles } from '@material-ui/core';
import EntityIndicatorsLines, {
  entityIndicatorsLinesQuery,
} from './EntityIndicatorsLines';
import ListLines from '../../../../components/list_lines/ListLines';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import StixRelationCreationFromEntity from '../../common/stix_relations/StixRelationCreationFromEntity';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
});

class EntityIndicators extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: false,
      lastSeenStart: null,
      lastSeenStop: null,
      targetEntityTypes: ['Indicator'],
      view: 'lines',
      inferred: false,
    };
  }

  handleChangeInferred() {
    this.setState({
      inferred: !this.state.inferred,
      sortBy: !this.state.inferred ? null : this.state.sortBy,
    });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityLink } = this.props;
    const dataColumns = {
      main_observable_type: {
        label: 'Type',
        width: '10%',
        isSortable: false,
      },
      name: {
        label: 'Name',
        width: '30%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      weight: {
        label: 'Confidence level',
        isSortable: true,
      },
    };
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={this.handleSort.bind(this)}
        displayImport={false}
        secondaryAction={true}
      >
        <QueryRenderer
          query={entityIndicatorsLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <EntityIndicatorsLines
              data={props}
              paginationOptions={paginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              initialLoading={props === null}
            />
          )}
        />
      </ListLines>
    );
  }

  render() {
    const {
      t, entityId, relationType, classes,
    } = this.props;
    const {
      view,
      targetEntityTypes,
      sortBy,
      orderAsc,
      lastSeenStart,
      lastSeenStop,
      inferred,
    } = this.state;
    const paginationOptions = {
      inferred,
      toTypes: targetEntityTypes,
      fromId: entityId,
      relationType,
      lastSeenStart: lastSeenStart || null,
      lastSeenStop: lastSeenStop || null,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
        >
          <Grid container={true} spacing={1}>
            <Grid item={true} xs="auto">
              <FormControlLabel
                style={{ paddingTop: 5, marginRight: 15 }}
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
        {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        <StixRelationCreationFromEntity
          entityId={entityId}
          isFrom={false}
          targetEntityTypes={['Indicator']}
          paginationOptions={paginationOptions}
        />
      </div>
    );
  }
}

EntityIndicators.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(EntityIndicators);
