import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, last, map, toPairs } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import Tooltip from '@mui/material/Tooltip';
import MenuItem from '@mui/material/MenuItem';
import {
  ArrowDownward,
  ArrowUpward,
  ViewModuleOutlined,
  ViewListOutlined,
  FileDownloadOutlined,
} from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
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
    marginTop: 2,
  },
  sortFieldLabel: {
    margin: '10px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-3px 0 0 15px',
  },
  filters: {
    float: 'left',
    margin: '5px 0 0 15px',
  },
  filter: {
    marginRight: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
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
          {availableFilterKeys && availableFilterKeys.length > 0 && (
            <Filters
              availableFilterKeys={availableFilterKeys}
              handleAddFilter={handleAddFilter}
            />
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
              size="small"
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
            size="large"
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
            {numberOfElements && (
              <div style={{ float: 'left', padding: '15px 5px 0 0' }}>
                <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>{' '}
                {t('entitie(s)')}
              </div>
            )}
            {(typeof handleChangeView === 'function'
              || typeof handleToggleExports === 'function') && (
              <ToggleButtonGroup
                size="small"
                color="secondary"
                value="cards"
                exclusive={true}
                onChange={(_, value) => {
                  if (value && value === 'export') {
                    handleToggleExports();
                  } else if (value) {
                    handleChangeView(value);
                  }
                }}
                style={{ margin: '7px 0 0 5px' }}
              >
                {typeof handleChangeView === 'function' && (
                  <ToggleButton value="cards" aria-label="cards">
                    <Tooltip title={t('Cards view')}>
                      <ViewModuleOutlined fontSize="small" />
                    </Tooltip>
                  </ToggleButton>
                )}
                <ToggleButton value="lines" aria-label="lines">
                  <Tooltip title={t('Lines view')}>
                    <ViewListOutlined color="primary" fontSize="small" />
                  </Tooltip>
                </ToggleButton>
                {typeof handleToggleExports === 'function' && (
                  <ToggleButton value="export" aria-label="export">
                    <Tooltip title={t('Open export panel')}>
                      <FileDownloadOutlined
                        color={openExports ? 'secondary' : 'primary'}
                        fontSize="small"
                      />
                    </Tooltip>
                  </ToggleButton>
                )}
              </ToggleButtonGroup>
            )}
          </div>
        </div>
        <div className="clearfix" />
        <div className={classes.cardsContainer}>{children}</div>
        {typeof handleToggleExports === 'function' && (
          <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
            <StixDomainObjectsExports
              open={openExports}
              handleToggle={handleToggleExports.bind(this)}
              paginationOptions={paginationOptions}
              exportEntityType={exportEntityType}
              context={exportContext}
            />
          </Security>
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
