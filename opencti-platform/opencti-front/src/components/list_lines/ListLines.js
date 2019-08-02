/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, toPairs } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import IconButton from '@material-ui/core/IconButton';
import {
  ArrowDropDown,
  ArrowDropUp,
  TableChart,
  Dashboard,
} from '@material-ui/icons';
import StixDomainEntitiesImportData from '../../private/components/common/stix_domain_entities/StixDomainEntitiesImportData';
import SearchInput from '../SearchInput';
import inject18n from '../i18n';

const styles = () => ({
  parameters: {
    float: 'left',
    marginTop: -10,
  },
  views: {
    float: 'right',
  },
  linesContainer: {
    marginTop: 10,
    paddingTop: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  sortIcon: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  headerItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  sortableHeaderItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
});

class ListLines extends Component {
  reverseBy(field) {
    this.props.handleSort(field, !this.props.orderAsc);
  }

  renderHeaderElement(field, label, width, isSortable) {
    const {
      classes, t, sortBy, orderAsc,
    } = this.props;
    if (isSortable) {
      return (
        <div
          key={field}
          className={classes.sortableHeaderItem}
          style={{ width }}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {sortBy === field ? (
            orderAsc ? (
              <ArrowDropDown classes={{ root: classes.sortIcon }} />
            ) : (
              <ArrowDropUp classes={{ root: classes.sortIcon }} />
            )
          ) : (
            ''
          )}
        </div>
      );
    }
    return (
      <div className={classes.headerItem} style={{ width }}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const {
      classes,
      handleSearch,
      handleChangeView,
      dataColumns,
      displayImport,
      children,
    } = this.props;
    return (
      <div>
        <div className={classes.parameters}>
          {typeof handleSearch === 'function' ? (
            <div style={{ float: 'left', marginRight: 20 }}>
              <SearchInput variant="small" onSubmit={handleSearch.bind(this)} />
            </div>
          ) : (
            ''
          )}
        </div>
        <div className={classes.views}>
          <div style={{ float: 'right', marginTop: -20 }}>
            {typeof handleChangeView === 'function' ? (
              <IconButton
                color="primary"
                classes={{ root: classes.button }}
                onClick={handleChangeView.bind(this, 'cards')}
              >
                <Dashboard />
              </IconButton>
            ) : (
              ''
            )}
            {typeof handleChangeView === 'function' ? (
              <IconButton
                color="secondary"
                classes={{ root: classes.button }}
                onClick={handleChangeView.bind(this, 'lines')}
              >
                <TableChart />
              </IconButton>
            ) : (
              ''
            )}
            {displayImport ? <StixDomainEntitiesImportData /> : ''}
          </div>
        </div>
        <div className="clearfix" />
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ root: classes.item }}
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
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {toPairs(dataColumns).map(dataColumn => this.renderHeaderElement(
                    dataColumn[0],
                    dataColumn[1].label,
                    dataColumn[1].width,
                    dataColumn[1].isSortable,
                  ))}
                </div>
              }
            />
          </ListItem>
          {children}
        </List>
      </div>
    );
  }
}

ListLines.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  children: PropTypes.object,
  handleSearch: PropTypes.func,
  handleSort: PropTypes.func.isRequired,
  handleChangeView: PropTypes.func,
  views: PropTypes.array,
  displayExport: PropTypes.bool,
  displayImport: PropTypes.bool,
  sortBy: PropTypes.string.isRequired,
  orderAsc: PropTypes.bool.isRequired,
  dataColumns: PropTypes.object.isRequired,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ListLines);
