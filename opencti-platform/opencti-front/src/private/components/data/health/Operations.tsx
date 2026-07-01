import { graphql, useLazyLoadQuery } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { OperationsQuery } from './__generated__/OperationsQuery.graphql';
import ItemBoolean from '../../../../components/ItemBoolean';
import OperationPopover from './OperationPopover';
import MaintenancePlanningEdition from './MaintenancePlanningEdition';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';

const operationsQuery = graphql`
  query OperationsQuery {
    dataSanityOperations {
      identifier
      display_name
      execution_type
      description
      eligible_entity_types
      is_running
      force_run
      last_run_date
      last_execution_time
      last_run_success
      last_run_message
      last_run_output
    }
  }
`;

const Operations = () => {
  const { t_i18n, fldt } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Operations | Health | Data'));

  const data = useLazyLoadQuery<OperationsQuery>(operationsQuery, {});

  const operations = data.dataSanityOperations.map((op) => ({
    id: op.identifier,
    display_name: op.display_name,
    description: op.description,
    execution_type: op.execution_type,
    eligible_entity_types: op.eligible_entity_types,
    is_running: op.is_running,
    force_run: op.force_run,
    last_run_date: op.last_run_date,
    last_execution_time: op.last_execution_time,
    last_run_success: op.last_run_success,
    last_run_message: op.last_run_message,
    last_run_output: op.last_run_output,
  }));

  type OperationRow = typeof operations[number];

  const getScheduleStatus = (op: OperationRow) => {
    if (op.is_running) return { label: t_i18n('Running'), status: true };
    if (op.force_run) return { label: t_i18n('Scheduled'), status: true };
    if (op.last_run_date) return { label: t_i18n('Done'), status: false };
    return { label: t_i18n('Idle'), status: false };
  };

  const getExecutionStatus = (op: OperationRow) => {
    if (!op.last_run_date) return { label: t_i18n('Never run'), status: null };
    if (op.last_run_success) return { label: t_i18n('Success'), status: true };
    return { label: t_i18n('Failed'), status: false };
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    display_name: {
      label: 'Name',
      percentWidth: 14,
      isSortable: false,
      render: (row: OperationRow) => <>{row.display_name}</>,
    },
    description: {
      label: 'Description',
      percentWidth: 18,
      isSortable: false,
      render: (row: OperationRow) => (
        <Tooltip title={row.description}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
            {row.description}
          </span>
        </Tooltip>
      ),
    },
    eligible_entity_types: {
      label: 'Entity types',
      percentWidth: 12,
      isSortable: false,
      render: (row: OperationRow) => (
        <>{row.eligible_entity_types.join(', ')}</>
      ),
    },
    execution_type: {
      label: 'Type',
      percentWidth: 7,
      isSortable: false,
      render: (row: OperationRow) => <>{row.execution_type}</>,
    },
    schedule_status: {
      label: 'Schedule',
      percentWidth: 9,
      isSortable: false,
      render: (row: OperationRow) => {
        const s = getScheduleStatus(row);
        return <ItemBoolean label={s.label} status={s.status} />;
      },
    },
    execution_status: {
      label: 'Result',
      percentWidth: 9,
      isSortable: false,
      render: (row: OperationRow) => {
        const s = getExecutionStatus(row);
        return <ItemBoolean label={s.label} status={s.status} />;
      },
    },
    last_run_date: {
      label: 'Last run',
      percentWidth: 11,
      isSortable: false,
      render: (row: OperationRow) => (
        <>{row.last_run_date ? fldt(row.last_run_date) : '-'}</>
      ),
    },
    last_execution_time: {
      label: 'Duration',
      percentWidth: 7,
      isSortable: false,
      render: (row: OperationRow) => (
        <>
          {row.last_execution_time != null
            ? `${(row.last_execution_time / 1000).toFixed(1)}s`
            : '-'}
        </>
      ),
    },
    impacted_elements: {
      label: 'Impact',
      percentWidth: 7,
      isSortable: false,
      render: (row: OperationRow) => {
        if (!row.last_run_output) return <>-</>;
        try {
          const output = JSON.parse(row.last_run_output);
          const total = output?.impact?.total ?? 0;
          const detail = output?.impact?.detail as Record<string, number> | undefined;
          const tooltipContent = detail
            ? Object.entries(detail).map(([key, count]) => `${key}: ${count}`).join('\n')
            : '';
          return (
            <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{tooltipContent}</span>}>
              <span>{total}</span>
            </Tooltip>
          );
        } catch {
          return <>-</>;
        }
      },
    },
  };

  return (
    <div data-testid="data-health-operations-page">
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Health') },
          { label: t_i18n('Operations'), current: true },
        ]}
        noMargin
      />
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10 }}>
        <MaintenancePlanningEdition />
      </div>
      <DataTableWithoutFragment
        dataColumns={dataColumns}
        storageKey="health_operations"
        data={operations}
        globalCount={operations.length}
        disableNavigation={true}
        disableLineSelection={true}
        disableToolBar={true}
        actions={(row: OperationRow) => (
          <OperationPopover operationName={row.id} />
        )}
      />
    </div>
  );
};

export default Operations;
