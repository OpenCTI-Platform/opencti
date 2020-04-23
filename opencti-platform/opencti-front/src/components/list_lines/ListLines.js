import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, toPairs } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import {
  ArrowDropDown,
  ArrowDropUp,
  Dashboard,
  TableChart,
} from '@material-ui/icons';
import Chip from '@material-ui/core/Chip';
import Tooltip from '@material-ui/core/Tooltip';
import { FileExportOutline } from 'mdi-material-ui';
import SearchInput from '../SearchInput';
import inject18n from '../i18n';
import StixDomainEntitiesExports from '../../private/components/common/stix_domain_entities/StixDomainEntitiesExports';
import Security, { KNOWLEDGE_KNGETEXPORT } from '../../utils/Security';
import Filters from '../../private/components/common/lists/Filters';

const styles = (theme) => ({
  container: {
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    padding: '0 0 50px 0',
  },
  containerOpenExports: {
    flexGrow: 1,
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '0 310px 50px 0',
  },
  parameters: {
    float: 'left',
    marginTop: -10,
  },
  views: {
    float: 'right',
  },
  linesContainer: {
    margin: '10px 0 0 0',
    padding: 0,
  },
  linesContainerBottomNav: {
    margin: '10px 0 90px 0',
    padding: 0,
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
  filters: {
    float: 'left',
    margin: '2px 0 0 10px',
  },
  filter: {
    marginRight: 10,
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
      const orderComponent = orderAsc ? (
        <ArrowDropDown classes={{ root: classes.sortIcon }} />
      ) : (
        <ArrowDropUp classes={{ root: classes.sortIcon }} />
      );
      return (
        <div
          key={field}
          className={classes.sortableHeaderItem}
          style={{ width }}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {sortBy === field ? orderComponent : ''}
        </div>
      );
    }
    return (
      <div className={classes.headerItem} style={{ width }} key={field}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const {
      t,
      classes,
      handleSearch,
      handleChangeView,
      disableCards,
      enableDuplicates,
      handleAddFilter,
      handleRemoveFilter,
      handleToggleExports,
      openExports,
      noPadding,
      dataColumns,
      secondaryAction,
      paginationOptions,
      keyword,
      filters,
      bottomNav,
      children,
      exportEntityType,
      exportContext,
      numberOfElements,
      availableFilterKeys,
    } = this.props;
    return (
      <div
        className={
          openExports && !noPadding
            ? classes.containerOpenExports
            : classes.container
        }
      >
        <div className={classes.parameters}>
          {typeof handleSearch === 'function' ? (
            <div style={{ float: 'left', marginRight: 20 }}>
              <SearchInput
                variant="small"
                onSubmit={handleSearch.bind(this)}
                keyword={keyword}
              />
            </div>
          ) : (
            ''
          )}
          {availableFilterKeys && availableFilterKeys.length > 0 ? (
            <Filters
              availableFilterKeys={availableFilterKeys}
              handleAddFilter={handleAddFilter}
              currentFilters={filters}
            />
          ) : (
            ''
          )}
          <div className={classes.filters}>
            {map(
              (filter) => map(
                (f) => (
                    <Chip
                      key={filter[0]}
                      classes={{ root: classes.filter }}
                      label={`${t(`filter_${filter[0]}`)}: ${
                        f.value === null ? t('No tag') : f.value
                      }`}
                      onDelete={handleRemoveFilter.bind(this, filter[0])}
                    />
                ),
                filter[1],
              ),
              toPairs(filters),
            )}
          </div>
        </div>
        <div className={classes.views}>
          <div style={{ float: 'right', marginTop: -20 }}>
            {numberOfElements ? (
              <div style={{ float: 'left', padding: '15px 5px 0 0' }}>
                <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>{' '}
                {t('entitie(s)')}
              </div>
            ) : (
              ''
            )}
            {typeof handleChangeView === 'function' && !disableCards ? (
              <Tooltip title={t('Cards view')}>
                <IconButton
                  color="primary"
                  onClick={handleChangeView.bind(this, 'cards')}
                >
                  <Dashboard />
                </IconButton>
              </Tooltip>
            ) : (
              ''
            )}
            {typeof handleChangeView === 'function' ? (
              <Tooltip title={t('Lines view')}>
                <IconButton
                  color="secondary"
                  onClick={handleChangeView.bind(this, 'lines')}
                >
                  <TableChart />
                </IconButton>
              </Tooltip>
            ) : (
              ''
            )}
            {typeof handleChangeView === 'function' && enableDuplicates ? (
              <Tooltip title={t('Detect duplicates')}>
                <IconButton
                  color="secondary"
                  onClick={handleChangeView.bind(this, 'duplicates')}
                >
                  <TableChart />
                </IconButton>
              </Tooltip>
            ) : (
              ''
            )}
            <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
              {typeof handleToggleExports === 'function' ? (
                <Tooltip title={t('Exports panel')}>
                  <IconButton
                    color={openExports ? 'secondary' : 'primary'}
                    onClick={handleToggleExports.bind(this)}
                  >
                    <FileExportOutline />
                  </IconButton>
                </Tooltip>
              ) : (
                ''
              )}
            </Security>
          </div>
        </div>
        <div className="clearfix" />
        <List
          classes={{
            root: bottomNav
              ? classes.linesContainerBottomNav
              : classes.linesContainer,
          }}
        >
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
                  {toPairs(dataColumns).map((dataColumn) => this.renderHeaderElement(
                    dataColumn[0],
                    dataColumn[1].label,
                    dataColumn[1].width,
                    dataColumn[1].isSortable,
                  ))}
                </div>
              }
            />
            {secondaryAction ? (
              <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
            ) : (
              ''
            )}
          </ListItem>
          {children}
        </List>
        {typeof handleToggleExports === 'function' ? (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixDomainEntitiesExports
              open={openExports}
              handleToggle={handleToggleExports.bind(this)}
              paginationOptions={paginationOptions}
              exportEntityType={exportEntityType}
              context={exportContext}
            />
          </Security>
        ) : (
          ''
        )}
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
  disableCards: PropTypes.bool,
  enableDuplicates: PropTypes.bool,
  handleAddFilter: PropTypes.func,
  handleRemoveFilter: PropTypes.func,
  handleToggleExports: PropTypes.func,
  openExports: PropTypes.bool,
  noPadding: PropTypes.bool,
  views: PropTypes.array,
  exportEntityType: PropTypes.string,
  exportContext: PropTypes.string,
  keyword: PropTypes.string,
  filters: PropTypes.object,
  sortBy: PropTypes.string,
  orderAsc: PropTypes.bool.isRequired,
  dataColumns: PropTypes.object.isRequired,
  paginationOptions: PropTypes.object,
  secondaryAction: PropTypes.bool,
  bottomNav: PropTypes.bool,
  numberOfElements: PropTypes.object,
  availableFilterKeys: PropTypes.array,
};

export default compose(inject18n, withStyles(styles))(ListLines);
