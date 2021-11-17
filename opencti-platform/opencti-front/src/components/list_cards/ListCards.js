import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, last, map, toPairs,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import {
  ArrowDownward,
  ArrowUpward,
  TableChartOutlined,
  DashboardOutlined,
} from '@material-ui/icons';
import Chip from '@material-ui/core/Chip';
import Tooltip from '@material-ui/core/Tooltip';
import { FileExportOutline } from 'mdi-material-ui';
import SearchInput from '../SearchInput';
import inject18n from '../i18n';
import StixDomainObjectsExports from '../../private/components/common/stix_domain_objects/StixDomainObjectsExports';
import Security, { KNOWLEDGE_KNGETEXPORT } from '../../utils/Security';
import Filters from '../../private/components/common/lists/Filters';
import { truncate } from '../../utils/String';

const styles = (theme) => ({
  container: {
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    marginLeft: -10,
  },
  containerOpenExports: {
    flexGrow: 1,
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    margin: '0 300px 0 -10px',
  },
  parameters: {
    float: 'left',
    margin: '-10px 0 0 15px',
  },
  views: {
    display: 'flex',
    float: 'right',
  },
  cardsContainer: {
    marginTop: 10,
    paddingTop: 0,
  },
  sortField: {
    float: 'left',
  },
  sortFieldLabel: {
    margin: '10px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
  filters: {
    float: 'left',
    margin: '2px 0 0 15px',
  },
  filter: {
    marginRight: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.chip,
    marginRight: 10,
  },
});

class ListCards extends Component {
  sortBy(event) {
    this.props.handleSort(event.target.value, this.props.orderAsc);
  }

  reverse() {
    this.props.handleSort(this.props.sortBy, !this.props.orderAsc);
  }

  render() {
    const {
      t,
      classes,
      handleSearch,
      handleChangeView,
      handleAddFilter,
      handleRemoveFilter,
      handleToggleExports,
      openExports,
      dataColumns,
      paginationOptions,
      keyword,
      filters,
      sortBy,
      orderAsc,
      children,
      exportEntityType,
      exportContext,
      numberOfElements,
      availableFilterKeys,
    } = this.props;
    return (
      <div
        className={
          openExports ? classes.containerOpenExports : classes.container
        }
      >
        <div className={classes.parameters}>
          <div style={{ float: 'left', marginRight: 20 }}>
            <SearchInput
              variant="small"
              onSubmit={handleSearch.bind(this)}
              keyword={keyword}
            />
          </div>
          {availableFilterKeys && availableFilterKeys.length > 0 ? (
            <Filters
              availableFilterKeys={availableFilterKeys}
              handleAddFilter={handleAddFilter}
              currentFilters={filters}
            />
          ) : (
            ''
          )}
          <InputLabel
            classes={{ root: classes.sortFieldLabel }}
            style={{
              marginLeft:
                availableFilterKeys && availableFilterKeys.length > 0 ? 10 : 0,
            }}
          >
            {t('Sort by')}
          </InputLabel>
          <FormControl classes={{ root: classes.sortField }}>
            <Select
              name="sort-by"
              value={sortBy}
              onChange={this.sortBy.bind(this)}
              inputProps={{
                name: 'sort-by',
                id: 'sort-by',
              }}
            >
              {toPairs(dataColumns).map((dataColumn) => (
                <MenuItem key={dataColumn[0]} value={dataColumn[0]}>
                  {t(dataColumn[1].label)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <IconButton
            aria-label="Sort by"
            onClick={this.reverse.bind(this)}
            classes={{ root: classes.sortIcon }}
          >
            {orderAsc ? <ArrowDownward /> : <ArrowUpward />}
          </IconButton>
          <div className={classes.filters}>
            {map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const values = (
                <span>
                  {map(
                    (n) => (
                      <span key={n.value}>
                        {n.value && n.value.length > 0
                          ? truncate(n.value, 15)
                          : t('No label')}{' '}
                        {last(currentFilter[1]).value !== n.value && (
                          <code>OR</code>
                        )}{' '}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <span>
                  <Chip
                    key={currentFilter[0]}
                    classes={{ root: classes.filter }}
                    label={
                      <div>
                        <strong>{label}</strong>: {values}
                      </div>
                    }
                    onDelete={handleRemoveFilter.bind(this, currentFilter[0])}
                  />
                  {last(toPairs(filters))[0] !== currentFilter[0] && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={t('AND')}
                    />
                  )}
                </span>
              );
            }, toPairs(filters))}
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
            {typeof handleChangeView === 'function' ? (
              <Tooltip title={t('Cards view')}>
                <IconButton
                  color="secondary"
                  onClick={handleChangeView.bind(this, 'cards')}
                >
                  <DashboardOutlined />
                </IconButton>
              </Tooltip>
            ) : (
              ''
            )}
            {typeof handleChangeView === 'function' ? (
              <Tooltip title={t('Lines view')}>
                <IconButton
                  color="primary"
                  onClick={handleChangeView.bind(this, 'lines')}
                >
                  <TableChartOutlined />
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
        <div className={classes.cardsContainer}>{children}</div>
        {typeof handleToggleExports === 'function' ? (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixDomainObjectsExports
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

ListCards.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  children: PropTypes.object,
  handleSearch: PropTypes.func.isRequired,
  handleSort: PropTypes.func.isRequired,
  handleChangeView: PropTypes.func,
  handleAddFilter: PropTypes.func,
  handleRemoveFilter: PropTypes.func,
  handleToggleExports: PropTypes.func,
  openExports: PropTypes.bool,
  views: PropTypes.array,
  exportEntityType: PropTypes.string,
  exportContext: PropTypes.string,
  keyword: PropTypes.string,
  filters: PropTypes.object,
  sortBy: PropTypes.string.isRequired,
  orderAsc: PropTypes.bool.isRequired,
  dataColumns: PropTypes.object.isRequired,
  paginationOptions: PropTypes.object,
  numberOfElements: PropTypes.object,
  availableFilterKeys: PropTypes.array,
};

export default compose(inject18n, withStyles(styles))(ListCards);
