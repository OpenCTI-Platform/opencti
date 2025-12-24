import React, { useState } from 'react';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/material/styles';
import {
  StixCoreObjectHistoryLinesQuery,
  StixCoreObjectHistoryLinesQuery$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import { useInitCreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';
import SearchInput from '../../../../components/SearchInput';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import type { Theme } from '../../../../components/Theme';

type StixCoreObjectHistoryProps = {
  stixCoreObjectId: string;
  withoutRelations?: boolean;
};

const StixCoreObjectHistory = ({ stixCoreObjectId, withoutRelations }: StixCoreObjectHistoryProps) => {
  useInitCreateRelationshipContext();

  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [entitySearchTerm, setEntitySearchTerm] = useState<string>('');
  const [relationsSearchTerm, setRelationsSearchTerm] = useState<string>('');

  const handleSearchEntity = (value: string) => setEntitySearchTerm(value);

  const handleSearchRelations = (value: string) => setRelationsSearchTerm(value);

  const objectsPaginationOptions: StixCoreObjectHistoryLinesQuery$variables = {
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: ['context_data.id'], values: [stixCoreObjectId] },
        {
          key: ['event_type'],
          values: ['mutation', 'create', 'update', 'delete', 'merge'],
        },
      ],
    },
    first: 20,
    orderBy: 'timestamp',
    orderMode: 'desc',
    search: entitySearchTerm,
  };

  const objectsQueryRef = useQueryLoading<StixCoreObjectHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    objectsPaginationOptions,
  );

  const relationsPaginationOptions: StixCoreObjectHistoryLinesQuery$variables = {
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['event_type'],
          values: ['create', 'delete', 'mutation'], // retro-compatibility
        },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          {
            key: ['event_scope'],
            values: ['create', 'delete'],
          },
          {
            key: ['event_scope'],
            values: [], // if event_scope is null, event_type is not
            operator: 'nil',
          },
        ],
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          {
            key: ['context_data.from_id'],
            values: [stixCoreObjectId],
          },
          {
            key: ['context_data.to_id'],
            values: [stixCoreObjectId],
          },
        ],
        filterGroups: [],
      }],
    },
    first: 20,
    orderBy: 'timestamp',
    orderMode: 'desc',
    search: relationsSearchTerm,
  };

  const relationsQueryRef = useQueryLoading<StixCoreObjectHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    relationsPaginationOptions,
  );

  return (
    <div style={{ height: '100%' }} data-testid="sco-history-content">
      <Grid
        container
        spacing={3}
        sx={{
          marginBottom: theme.spacing(2),
        }}
      >
        <Grid
          item
          xs={withoutRelations ? 12 : 6}
        >
          {objectsQueryRef && (
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <StixCoreObjectHistoryLines
                title={t_i18n('Entity')}
                queryRef={objectsQueryRef}
                isRelationLog={false}
                paginationOptions={objectsPaginationOptions}
                action={(
                  <SearchInput
                    variant="thin"
                    onSubmit={handleSearchEntity}
                    keyword={entitySearchTerm}
                  />
                )}
              />
            </React.Suspense>
          )}
        </Grid>
        {!withoutRelations && (
          <Grid item xs={6}>
            {relationsQueryRef && (
              <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                <StixCoreObjectHistoryLines
                  title={t_i18n('Relations of the entity')}
                  queryRef={relationsQueryRef}
                  isRelationLog={true}
                  paginationOptions={relationsPaginationOptions}
                  action={(
                    <SearchInput
                      variant="thin"
                      onSubmit={handleSearchRelations}
                      keyword={relationsSearchTerm}
                    />
                  )}
                />
              </React.Suspense>
            )}
          </Grid>
        )}
      </Grid>
    </div>
  );
};

export default StixCoreObjectHistory;
