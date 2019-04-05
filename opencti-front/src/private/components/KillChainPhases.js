/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { ArrowDropDown, ArrowDropUp } from '@material-ui/icons';
import { QueryRenderer } from '../../relay/environment';
import KillChainPhasesLines, {
  killChainPhasesLinesQuery,
} from './kill_chain_phase/KillChainPhasesLines';
import inject18n from '../../components/i18n';
import KillChainPhaseCreation from './kill_chain_phase/KillChainPhaseCreation';

const styles = () => ({
  linesContainer: {
    marginTop: 0,
    paddingTop: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
});

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '-3px 0 0 5px',
    padding: 0,
    top: '0px',
  },
  kill_chain_name: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
  },
  phase_name: {
    float: 'left',
    width: '35%',
    fontSize: 12,
    fontWeight: '700',
  },
  phase_order: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  created: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

class KillChainPhases extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'kill_chain_name', orderAsc: true };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label) {
    const { t } = this.props;
    return (
      <div
        style={inlineStyles[field]}
        onClick={this.reverseBy.bind(this, field)}
      >
        <span>{t(label)}</span>
        {this.state.sortBy === field ? (
          this.state.orderAsc ? (
            <ArrowDropDown style={inlineStyles.iconSort} />
          ) : (
            <ArrowDropUp style={inlineStyles.iconSort} />
          )
        ) : (
          ''
        )}
      </div>
    );
  }

  render() {
    const { classes } = this.props;
    const paginationOptions = {
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ default: classes.item }}
            divider={false}
            style={{ paddingTop: 0 }}
          >
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                #
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {this.SortHeader('kill_chain_name', 'Kill chain')}
                  {this.SortHeader('phase_name', 'Phase name')}
                  {this.SortHeader('phase_order', 'Order')}
                  {this.SortHeader('created', 'Creation date')}
                </div>
              }
            />
          </ListItem>
          <QueryRenderer
            query={killChainPhasesLinesQuery}
            variables={{
              count: 25,
              orderBy: this.state.sortBy,
              orderMode: this.state.orderAsc ? 'asc' : 'desc',
            }}
            render={({ props }) => {
              if (props) {
                // Done
                return (
                  <KillChainPhasesLines
                    data={props}
                    paginationOptions={paginationOptions}
                  />
                );
              }
              // Loading
              return <KillChainPhasesLines data={null} dummy={true} />;
            }}
          />
        </List>
        <KillChainPhaseCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

KillChainPhases.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(KillChainPhases);
