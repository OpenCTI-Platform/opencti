import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/material/styles';
import { StixCoreObjectHistoryLines_data$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLines_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';
import SearchInput from '../../../../components/SearchInput';
import Loader, { LoaderVariant } from '../../../../components/Loader';

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
          <QueryRenderer
            query={stixCoreObjectHistoryLinesQuery}
            variables={{
              filters: {
                mode: 'and',
                filterGroups: [],
                filters: [
                  { key: 'context_data.id', values: [stixCoreObjectId] },
                  {
                    key: 'event_type',
                    values: ['mutation', 'create', 'update', 'delete', 'merge'],
                  },
                ],
              },
              first: 20,
              orderBy: 'timestamp',
              orderMode: 'desc',
              search: entitySearchTerm,
            }}
            render={({ props }: { props: StixCoreObjectHistoryLines_data$data }) => {
              if (props) {
                return (
                  <StixCoreObjectHistoryLines
                    stixCoreObjectId={stixCoreObjectId}
                    data={props}
                    isRelationLog={false}
                  />
                );
              }
              return <Loader variant={LoaderVariant.inElement} />;
            }}
          />
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
                keyword={entitySearchTerm}
              />
            </div>
            <div className="clearfix" />
            <QueryRenderer
              query={stixCoreObjectHistoryLinesQuery}
              variables={{
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'event_type',
                      values: ['create', 'delete', 'mutation'], // retro-compatibility
                    },
                  ],
                  filterGroups: [{
                    mode: 'or',
                    filters: [
                      {
                        key: 'event_scope',
                        values: ['create', 'delete'],
                      },
                      {
                        key: 'event_scope',
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
                        key: 'context_data.from_id',
                        values: [stixCoreObjectId],
                      },
                      {
                        key: 'context_data.to_id',
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
              }}
              render={({ props }: { props: StixCoreObjectHistoryLines_data$data }) => {
                if (props) {
                  return (
                    <StixCoreObjectHistoryLines
                      stixCoreObjectId={stixCoreObjectId}
                      data={props}
                      isRelationLog={true}
                    />
                  );
                }
                return <Loader variant={LoaderVariant.inElement} />;
              }}
            />
          </Grid>
        )}
      </Grid>
    </div>
  );
};

export default StixCoreObjectHistory;
