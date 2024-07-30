import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import IndicatorAddObservables from './IndicatorAddObservables';
import IndicatorObservablePopover from './IndicatorObservablePopover';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';

const IndicatorObservablesComponent = ({ indicator }) => {
  const [deleted, setDeleted] = useState([]);
  const { t_i18n } = useFormatter();
  const [ref, setRef] = useState(null);

  const onDelete = (id) => {
    setDeleted([id, ...deleted]);
  };

  const observables = indicator.observables.edges.filter((e) => !deleted.includes(e.node.id))
    .map((e) => e.node);
  const observablesGlobalCount = indicator.observables.pageInfo.globalCount;

  return (
    <div style={{ marginTop: 20, height: 300 }} ref={(r) => setRef(r)}>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Based on')}
      </Typography>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IndicatorAddObservables
          indicator={indicator}
          indicatorObservables={indicator.observables.edges}
        />
      </Security>
      <div className="clearfix" />
      <DataTableWithoutFragment
        dataColumns={{
          entity_type: {
            percentWidth: 20,
            isSortable: false,
          },
          observable_value: {
            percentWidth: 60,
            isSortable: false,
          },
          created_at: {
            percentWidth: 20,
            isSortable: false,
          },
        }}
        data={observables}
        globalCount={observablesGlobalCount}
        rootRef={ref}
        storageKey={`indicator-observables-${indicator.id}`}
        variant={DataTableVariant.inline}
        disableNavigation
        actions={(observable) => (
          <IndicatorObservablePopover
            indicatorId={indicator.id}
            observableId={observable.id}
            onDelete={() => onDelete(observable.id)}
          />
        )}
      />
    </div>
  );
};

const IndicatorObservables = createFragmentContainer(
  IndicatorObservablesComponent,
  {
    indicator: graphql`
      fragment IndicatorObservables_indicator on Indicator {
        id
        name
        parent_types
        entity_type
        observables(first: 100) {
          edges {
            node {
              id
              entity_type
              parent_types
              observable_value
              created_at
              updated_at
            }
          }
          pageInfo {
            globalCount
          }
        }
      }
    `,
  },
);

export default IndicatorObservables;
