import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/material/styles';
import { StixCoreObjectHistoryLinesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';
import SearchInput from '../../../../components/SearchInput';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

type StixCoreObjectHistoryProps = {
  stixCoreObjectId: string;
  withoutRelations?: boolean;
};

const StixCoreObjectHistory = ({ stixCoreObjectId, withoutRelations }: StixCoreObjectHistoryProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const [entitySearchTerm, setEntitySearchTerm] = useState<string>('');
  const [relationsSearchTerm, setRelationsSearchTerm] = useState<string>('');

  const handleSearchEntity = (value: string) => setEntitySearchTerm(value);

  const handleSearchRelations = (value: string) => setRelationsSearchTerm(value);

  const objectsQueryRef = useQueryLoading<StixCoreObjectHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    {
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
    },
  );

  const relationsQueryRef = useQueryLoading<StixCoreObjectHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    {
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
    },
  );

  return (
    <div style={{ height: '100%' }}>
      <Grid
        container
        spacing={3}
        sx={{
          marginBottom: theme.spacing(2),
        }}
        data-testid='sco-history-content'
      >
        <Grid
          item
          xs={withoutRelations ? 12 : 6}
        >
          <Typography
            variant="h4"
            gutterBottom
            style={{ float: 'left' }}
          >
            {t_i18n('Entity')}
          </Typography>
          <div style={{ float: 'right', marginTop: -15 }}>
            <SearchInput
              variant="thin"
              onSubmit={handleSearchEntity}
              keyword={entitySearchTerm}
            />
          </div>
          <div className="clearfix" />
          {objectsQueryRef
            && <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
               >
              <StixCoreObjectHistoryLines
                queryRef={objectsQueryRef}
                isRelationLog={false}
              />
            </React.Suspense>
            }
        </Grid>
        {!withoutRelations && (
          <Grid item xs={6}>
            <Typography
              variant="h4"
              gutterBottom
              style={{ float: 'left' }}
            >
              {t_i18n('Relations of the entity')}
            </Typography>
            <div style={{ float: 'right', marginTop: -15 }}>
              <SearchInput
                variant="thin"
                onSubmit={handleSearchRelations}
                keyword={relationsSearchTerm}
              />
            </div>
            <div className="clearfix" />
            {relationsQueryRef
              && <React.Suspense
                fallback={<Loader variant={LoaderVariant.inElement} />}
                 >
                <StixCoreObjectHistoryLines
                  queryRef={relationsQueryRef}
                  isRelationLog={true}
                />
              </React.Suspense>
            }
          </Grid>
        )}
      </Grid>
    </div>
  );
};

export default StixCoreObjectHistory;
