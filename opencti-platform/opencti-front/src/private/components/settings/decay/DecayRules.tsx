import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { buildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import CustomizationMenu from '../CustomizationMenu';
import DecayRuleCreation from './DecayRuleCreation';
import { DecayRulesLineDummy } from './DecayRulesLine';
import DecayRulesLines, { decayRulesLinesQuery } from './DecayRulesLines';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import ListLines from '../../../../components/list_lines/ListLines';
import type { Theme } from '../../../../components/Theme';
import { DecayRulesLinesPaginationQuery, DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';
import { DecayRulesLine_node$data } from './__generated__/DecayRulesLine_node.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { INDICATOR_DECAY_MANAGER } from '../../../../utils/platformModulesHelper';

const LOCAL_STORAGE_KEY = 'view-decay-rules';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));
const DecayRules = () => {
  const classes = useStyles();
  const { fd, t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<DecayRulesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'order',
      orderAsc: false,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const { sortBy, orderAsc, searchTerm, filters, numberOfElements } = viewStorage;
  const contextFilters = buildEntityTypeBasedFilterContext('DecayRule', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DecayRulesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<DecayRulesLinesPaginationQuery>(
    decayRulesLinesQuery,
    queryPaginationOptions,
  );

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: false,
        render: (node: DecayRulesLine_node$data) => node.name,
      },
      created_at: {
        label: 'Creation date',
        width: '20%',
        isSortable: false,
        render: (node: DecayRulesLine_node$data) => fd(node.created_at),
      },
      appliedIndicatorsCount: {
        label: 'Impacted indicators',
        width: '20%',
        isSortable: false,
        render: (node: DecayRulesLine_node$data) => node.appliedIndicatorsCount,
      },
      active: {
        label: 'Active',
        width: '15%',
        isSortable: false,
        render: (node: DecayRulesLine_node$data) => (
          <ItemBoolean
            variant="inList"
            label={node.active ? t_i18n('Yes') : t_i18n('No')}
            status={node.active}
          />
        ),
      },
      order: {
        label: 'Order',
        width: '10%',
        isSortable: false,
        render: (node: DecayRulesLine_node$data) => node.order,
      },
    };

    const { platformModuleHelpers } = useAuth();
    if (!platformModuleHelpers.isIndicatorDecayManagerEnable()) {
      return (
        <div style={{ width: '100%', marginTop: 10 }}>
          <Alert
            severity="info"
            variant="outlined"
            style={{ padding: '0px 10px 0px 10px' }}
            classes={{ message: classes.info }}
          >
            {t_i18n(platformModuleHelpers.generateDisableMessage(INDICATOR_DECAY_MANAGER))}
          </Alert>
        </div>
      );
    }

    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        displayImport={false}
        secondaryAction={false}
        keyword={searchTerm}
        numberOfElements={numberOfElements}
        message={t_i18n(
          'Decay rules are applied on indicators by priority order (from greatest to lowest, lowest being 0). '
          + 'There are three built-in rules applied by default that are not editable, you can add a custom decay rule and define its priority order.',
        )}
      >
        {queryRef && (
        <React.Suspense
          fallback={
            <>
              {Array(20)
                .fill(0)
                .map((_, idx) => (
                  <DecayRulesLineDummy
                    key={idx}
                    dataColumns={dataColumns}
                  />
                ))}
            </>
            }
        >
          <DecayRulesLines
            queryRef={queryRef}
            paginationOptions={paginationOptions}
            dataColumns={dataColumns}
          />
        </React.Suspense>
        )}
      </ListLines>
    );
  };

  return (
    <div className={classes.container}>
      <CustomizationMenu />
      {renderLines()}
      <DecayRuleCreation paginationOptions={queryPaginationOptions} />
    </div>
  );
};

export default DecayRules;
