import React from 'react';
import Grid from '@mui/material/Grid';
import { GenericAttackCardDummy } from '@components/common/cards/GenericAttackCard';
import { makeStyles } from '@mui/styles';
import { IntrusionSetsCardsPaginationQuery, IntrusionSetsCardsPaginationQuery$variables } from './intrusion_sets/__generated__/IntrusionSetsCardsPaginationQuery.graphql';
import ListCards from '../../../components/list_cards/ListCards';
import IntrusionSetsCards, { intrusionSetsCardsQuery } from './intrusion_sets/IntrusionSetsCards';
import IntrusionSetCreation from './intrusion_sets/IntrusionSetCreation';
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

const LOCAL_STORAGE_KEY = 'intrusionSets';

const IntrusionSets = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IntrusionSetsCardsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;

  const queryRef = useQueryLoading<IntrusionSetsCardsPaginationQuery>(
    intrusionSetsCardsQuery,
    paginationOptions,
  );

  const renderCards = () => {
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
            { text: t_i18n('Intrusion sets') },
          ]}
        >
          <div className={ classes.header }>{t_i18n('Intrusion sets')}</div>
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
          exportContext={{ entity_type: 'Intrusion-Set' }}
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
                <Grid container={true} spacing={3} style={{ paddingLeft: 17 }}>
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
              <IntrusionSetsCards
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
        <IntrusionSetCreation paginationOptions={paginationOptions} />
      </Security>
    </>
  );
};

export default IntrusionSets;
