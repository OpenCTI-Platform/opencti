import React from 'react';
import * as PropTypes from 'prop-types';
import { compose, toPairs } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import Tooltip from '@mui/material/Tooltip';
import MenuItem from '@mui/material/MenuItem';
import { ArrowDownward, ArrowUpward, FileDownloadOutlined, ViewListOutlined, ViewModuleOutlined } from '@mui/icons-material';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { UserContext } from '../../utils/hooks/useAuth';
import Filters from '../../private/components/common/lists/Filters';
import SearchInput from '../SearchInput';
import StixDomainObjectsExports from '../../private/components/common/stix_domain_objects/StixDomainObjectsExports';
import Security from '../../utils/Security';
import { KNOWLEDGE_KNGETEXPORT } from '../../utils/hooks/useGranted';
import FilterIconButton from '../FilterIconButton';
import { export_max_size } from '../../utils/utils';
import { Stack } from '@mui/material';
import { useFormatter } from '../i18n';

const styles = (theme) => ({
  parameters: {
    display: 'flex',
    gap: theme.spacing(1),
    marginBottom: theme.spacing(2),
    flexWrap: 'wrap',
    alignItems: 'center',
  },
  sortFieldContainer: {
    display: 'flex',
    gap: theme.spacing(1),
    alignItems: 'center',
  },
  cardsContainer: {
    margin: '10px 0 0 -15px',
    paddingTop: 0,
  },
  sortFieldLabel: {
    fontSize: 14,
  },
  filler: {
    flex: 'auto',
  },
});

const ListCards = (props) => {
  const { t_i18n } = useFormatter();
  const handleSortBy = (event) => {
    props.handleSort(event.target.value, props.orderAsc);
  };

  const reverse = () => {
    props.handleSort(props.sortBy, !props.orderAsc);
  };

  const {

    classes,

    handleSearch,

    handleChangeView,

    handleAddFilter,

    handleRemoveFilter,

    handleSwitchGlobalMode,

    handleSwitchLocalMode,

    handleToggleExports,

    openExports,

    dataColumns,

    paginationOptions,

    keyword,

    filters,

    sortBy,

    orderAsc,

    children,

    exportContext,

    numberOfElements,

    helpers,

    createButton,

    additionalHeaderButtons,

  } = props;
  const exportDisabled = numberOfElements && numberOfElements.number > export_max_size;
  const entityType = exportContext?.entity_type;
  return (
    <UserContext.Consumer>
      {({ schema }) => {
        const filterKeysMap = schema.filterKeysSchema.get(entityType) ?? new Map();
        const availableFilterKeys = Array.from(filterKeysMap.keys());
        return (
          <>
            <div className={classes.parameters}>
              <SearchInput
                variant="small"
                onSubmit={handleSearch.bind(this)}
                keyword={keyword}
              />
              {availableFilterKeys.length > 0 && (
                <Filters
                  helpers={helpers}
                  availableFilterKeys={availableFilterKeys}
                  handleAddFilter={handleAddFilter}
                  handleSwitchGlobalMode={handleSwitchGlobalMode}
                  handleSwitchLocalMode={handleSwitchLocalMode}
                  searchContext={{
                    entityTypes: entityType ? [entityType] : [],
                  }}
                />
              )}
              <div className={classes.sortFieldContainer}>
                <InputLabel classes={{ root: classes.sortFieldLabel }}>
                  {t_i18n('Sort by')}
                </InputLabel>
                <FormControl>
                  <Select
                    name="sort-by"
                    value={sortBy}
                    size="small"
                    variant="outlined"
                    onChange={handleSortBy}
                    inputProps={{
                      name: 'sort-by',
                      id: 'sort-by',
                    }}
                  >
                    <MenuItem key="_score" value="_score">
                      {t_i18n('Score')}
                    </MenuItem>
                    {toPairs(dataColumns).map((dataColumn) => (
                      <MenuItem key={dataColumn[0]} value={dataColumn[0]}>
                        {t_i18n(dataColumn[1].label)}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <IconButton
                  aria-label="Sort by"
                  onClick={reverse}
                  size="small"
                >
                  {orderAsc ? (
                    <ArrowDownward fontSize="small" />
                  ) : (
                    <ArrowUpward fontSize="small" />
                  )}
                </IconButton>
              </div>
              <div className={classes.filler} />
              <Stack direction="row" gap={1}>
                {numberOfElements && (
                  <div style={{ alignSelf: 'center' }}>
                    <strong>{`${numberOfElements.number}${numberOfElements.symbol}`}</strong>{' '}
                    {t_i18n('entitie(s)')}
                  </div>
                )}
                {(typeof handleChangeView === 'function'
                  || typeof handleToggleExports === 'function') && (
                  <ToggleButtonGroup
                    size="small"
                    value="cards"
                    exclusive={true}
                    onChange={(_, value) => {
                      if (value && value === 'export') {
                        handleToggleExports();
                      } else if (value) {
                        handleChangeView(value);
                      }
                    }}
                  >
                    {typeof handleChangeView === 'function' && (
                      <Tooltip title={t_i18n('Cards view')}>
                        <ToggleButton value="cards" aria-label="cards">
                          <ViewModuleOutlined fontSize="small" color="primary" />
                        </ToggleButton>
                      </Tooltip>
                    )}
                    {typeof handleChangeView === 'function' && (
                      <Tooltip title={t_i18n('Lines view')}>
                        <ToggleButton value="lines" aria-label="lines">
                          <ViewListOutlined fontSize="small" color="primary" />
                        </ToggleButton>
                      </Tooltip>
                    )}
                    {typeof handleToggleExports === 'function'
                      && !exportDisabled && (
                      <Tooltip title={t_i18n('Open export panel')}>
                        <ToggleButton value="export" aria-label="export">
                          <FileDownloadOutlined
                            color="primary"
                            fontSize="small"
                          />
                        </ToggleButton>
                      </Tooltip>
                    )}
                    {typeof handleToggleExports === 'function'
                      && exportDisabled && (
                      <Tooltip
                        title={`${
                          t_i18n(
                            'Export is disabled because too many entities are targeted (maximum number of entities is: ',
                          ) + export_max_size
                        })`}
                      >
                        <span>
                          <ToggleButton
                            size="small"
                            value="export"
                            aria-label="export"
                            disabled={true}
                          >
                            <FileDownloadOutlined fontSize="small" />
                          </ToggleButton>
                        </span>
                      </Tooltip>
                    )}
                  </ToggleButtonGroup>
                )}

                {
                  additionalHeaderButtons && (
                    <Stack
                      direction="row"
                      gap={1}
                      sx={{
                        '&:empty': {
                          display: 'none',
                        },
                      }}
                    >
                      {[...additionalHeaderButtons]}
                    </Stack>
                  )
                }

                {createButton}
              </Stack>
            </div>
            <FilterIconButton
              helpers={helpers}
              filters={filters}
              handleRemoveFilter={handleRemoveFilter}
              handleSwitchGlobalMode={handleSwitchGlobalMode}
              handleSwitchLocalMode={handleSwitchLocalMode}
              redirection
              entityTypes={entityType ? [entityType] : undefined}
              searchContext={{
                entityTypes: entityType ? [entityType] : [],
              }}
            />
            {typeof handleToggleExports === 'function' && (
              <Security needs={[KNOWLEDGE_KNGETEXPORT]}>
                <StixDomainObjectsExports
                  open={openExports}
                  handleToggle={handleToggleExports.bind(this)}
                  paginationOptions={paginationOptions}
                  exportContext={exportContext}
                />
              </Security>
            )}
            <div className={classes.cardsContainer}>{children}</div>
          </>
        );
      }}
    </UserContext.Consumer>
  );
};

ListCards.propTypes = {
  classes: PropTypes.object,
  children: PropTypes.object,
  handleSearch: PropTypes.func.isRequired,
  handleSort: PropTypes.func.isRequired,
  handleChangeView: PropTypes.func,
  handleAddFilter: PropTypes.func,
  handleRemoveFilter: PropTypes.func,
  handleToggleExports: PropTypes.func,
  openExports: PropTypes.bool,
  views: PropTypes.array,
  exportContext: PropTypes.object,
  keyword: PropTypes.string,
  filters: PropTypes.object,
  sortBy: PropTypes.string.isRequired,
  orderAsc: PropTypes.bool.isRequired,
  dataColumns: PropTypes.object.isRequired,
  paginationOptions: PropTypes.object,
  numberOfElements: PropTypes.object,
  helpers: PropTypes.object,
  createButton: PropTypes.object,
  additionalHeaderButtons: PropTypes.arrayOf[React.ReactNode],
};

export default compose(withStyles(styles))(ListCards);
