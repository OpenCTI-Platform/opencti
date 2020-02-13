import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import Drawer from '@material-ui/core/Drawer';
import Loader from '../../../../components/Loader';
import StixDomainEntityKillChainLines, {
  stixDomainEntityKillChainLinesStixRelationsQuery,
} from './StixDomainEntityKillChainLines';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';

const styles = (theme) => ({
  container: {
    marginTop: 15,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
});

class StixDomainEntityKillChain extends Component {
  constructor(props) {
    super(props);
    this.state = {
      inferred: false,
      searchTerm: '',
    };
  }

  handleChangeInferred() {
    this.setState({
      inferred: !this.state.inferred,
    });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  render() {
    const { inferred, searchTerm } = this.state;
    const {
      classes, stixDomainEntityId, entityLink, t,
    } = this.props;
    const paginationOptions = {
      fromId: stixDomainEntityId,
      toTypes: ['Attack-Pattern'],
      relationType: 'uses',
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
        <QueryRenderer
          query={stixDomainEntityKillChainLinesStixRelationsQuery}
          variables={{ first: 500, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <StixDomainEntityKillChainLines
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
      </div>
    );
  }
}

StixDomainEntityKillChain.propTypes = {
  stixDomainEntityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKillChain);
