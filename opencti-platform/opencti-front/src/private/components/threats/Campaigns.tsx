import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import { makeStyles } from '@mui/styles';
import { CampaignsCardsPaginationQuery$variables, CampaignsCardsPaginationQuery } from './campaigns/__generated__/CampaignsCardsPaginationQuery.graphql';
import ListCards from '../../../components/list_cards/ListCards';
import CampaignsCards, { campaignsCardsQuery } from './campaigns/CampaignsCards';
import CampaignCreation from './campaigns/CampaignCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import BreadcrumbHeader from '../../../components/BreadcrumbHeader';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
}));

const LOCAL_STORAGE_KEY = 'campaigns';

const Campaigns = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CampaignsCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      view: 'cards',
    },
  );
  const queryRef = useQueryLoading<CampaignsCardsPaginationQuery>(
    campaignsCardsQuery,
    paginationOptions,
  );
  const renderCards = () => {
    const {
      numberOfElements,
      filters,
      searchTerm,
      sortBy,
      orderAsc,
      openExports,
    } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
      },
      created: {
        label: 'Creation date',
      },
      modified: {
        label: 'Modification date',
      },
    };
    return (
      <>
        <BreadcrumbHeader
          path={[
            { text: t_i18n('Threats') },
            { text: t_i18n('Campaigns') },
          ]}
        >
          <div className={ classes.header }>{t_i18n('Campaigns')}</div>
        </BreadcrumbHeader>
        <ListCards
          helpers={helpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={helpers.handleSort}
          handleSearch={helpers.handleSearch}
          handleAddFilter={helpers.handleAddFilter}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={helpers.handleSwitchLocalMode}
          handleToggleExports={helpers.handleToggleExports}
          openExports={openExports}
          exportContext={{ entity_type: 'Campaign' }}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          availableFilterKeys={[
            'workflow_id',
            'objectLabel',
            'objectMarking',
            'createdBy',
            'source_reliability',
            'confidence',
            'creator_id',
            'created',
            'revoked',
            'targets',
            'name',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <Grid
                  container={true}
                  spacing={3}
                  style={{ paddingLeft: 17 }}
                >
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <Grid
                        item={true}
                        xs={3}
                        key={idx}
                      >
                        <GenericAttackCardDummy />
                      </Grid>
                    ))}
                </Grid>
              }
            >
              <CampaignsCards
                queryRef={queryRef}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                onLabelClick={helpers.handleAddFilter}
              />
            </React.Suspense>
          )}
        </ListCards>
      </>
    );
  };

  return (
    <>
      {renderCards()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CampaignCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default Campaigns;
