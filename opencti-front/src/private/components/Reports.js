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
import ReportsLines, { reportsLinesQuery } from './report/ReportsLines';
import inject18n from '../../components/i18n';
import ReportCreation from './report/ReportCreation';

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
  name: {
    float: 'left',
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  author: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  published: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  marking: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

class Reports extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'published', orderAsc: false };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label) {
    const { t } = this.props;
    return (
      <div style={inlineStyles[field]} onClick={this.reverseBy.bind(this, field)}>
        <span>{t(label)}</span>
        {this.state.sortBy === field ? this.state.orderAsc ? <ArrowDropDown style={inlineStyles.iconSort}/> : <ArrowDropUp style={inlineStyles.iconSort}/> : ''}
      </div>
    );
  }

  render() {
    const { classes, reportClass } = this.props;
    const paginationOptions = {
      reportClass: reportClass || '',
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem classes={{ default: classes.item }} divider={false} style={{ paddingTop: 0 }}>
            <ListItemIcon>
              <span style={{ padding: '0 8px 0 8px', fontWeight: 700, fontSize: 12 }}>#</span>
            </ListItemIcon>
            <ListItemText primary={
              <div>
                {this.SortHeader('name', 'Name')}
                {this.SortHeader('author', 'Author')}
                {this.SortHeader('published', 'Publication date')}
                {this.SortHeader('marking', 'Marking')}
              </div>
            }/>
          </ListItem>
          <QueryRenderer
            query={reportsLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => {
              if (props) { // Done
                return <ReportsLines data={props} paginationOptions={paginationOptions}/>;
              }
              // Loading
              return <ReportsLines data={null} dummy={true}/>;
            }}
          />
        </List>
        <ReportCreation paginationOptions={paginationOptions}/>
      </div>
    );
  }
}

Reports.propTypes = {
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Reports);
