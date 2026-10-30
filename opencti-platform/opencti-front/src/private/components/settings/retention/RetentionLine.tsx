import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { LayersClearOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { Chip } from '@filigran/design-system';
import { styled } from '@mui/material/styles';
import { RetentionLinesPaginationQuery$variables } from '@components/settings/retention/__generated__/RetentionLinesPaginationQuery.graphql';
import { RetentionLine_node$key } from '@components/settings/retention/__generated__/RetentionLine_node.graphql';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import RetentionPopover from './RetentionPopover';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../../components/FilterIconButton';
import { DataColumns } from '../../../../components/list_lines';
import ItemBoolean from '../../../../components/ItemBoolean';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const RetentionLineFragment = graphql`
    fragment RetentionLine_node on RetentionRule {
        id
        name
        max_retention
        retention_unit
        last_execution_date
        remaining_count
        filters
        scope
        active
    }
`;

interface RetentionLineProps {
  dataColumns: DataColumns;
  node: RetentionLine_node$key;
  paginationOptions: RetentionLinesPaginationQuery$variables;
}

export const RetentionLine: FunctionComponent<RetentionLineProps> = ({ dataColumns, node, paginationOptions }) => {
  const { ftdt, n, t_i18n } = useFormatter();
  const data = useFragment(RetentionLineFragment, node);

  const isActive = data.active;
  const filters = deserializeFilterGroupForFrontend(data.filters);
  let scopeSeverity: 'low' | 'info' | 'high' | 'critical' = 'low';
  let appliedOnContent = t_i18n('Everything');
  if (data.scope === 'file') {
    scopeSeverity = 'critical';
    appliedOnContent = t_i18n('Global files');
  } else if (data.scope === 'workbench') {
    scopeSeverity = 'info';
    appliedOnContent = t_i18n('All workbenches');
  } else if (data.scope === 'history') {
    scopeSeverity = 'critical';
    appliedOnContent = t_i18n('Knowledge history logs');
  } else if (data.scope === 'activity') {
    scopeSeverity = 'high';
    appliedOnContent = t_i18n('Activity logs');
  }
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: '50px' }}
      divider={true}
      secondaryAction={(
        <RetentionPopover
          retentionRuleId={data.id}
          paginationOptions={paginationOptions}
        />
      )}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <LayersClearOutlined />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem style={{ width: dataColumns.name.width }}>
              {data.name}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.max_retention.width }}
            >
              {data.max_retention} {t_i18n(data.retention_unit)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.last_execution_date.width }}
            >
              {ftdt(data.last_execution_date)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.remaining_count.width }}
            >
              {n(data.remaining_count)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.scope.width }}
            >
              <Chip
                severity={scopeSeverity}
                label={t_i18n(data.scope)}
              />
            </BodyItem>
            {dataColumns.active && (
              <BodyItem
                style={{ width: dataColumns.active.width }}
              >
                <ItemBoolean
                  status={isActive}
                  label={isActive ? t_i18n('Active') : t_i18n('Inactive')}
                />
              </BodyItem>
            )}
            {isFilterGroupNotEmpty(filters) ? (
              <FilterIconButton
                filters={filters}
                variant="small"
                redirection
              />
            ) : (
              <BodyItem style={{ width: dataColumns.filters.width }}>
                <span>{appliedOnContent}</span>
                {data.scope !== 'knowledge' && data.scope !== 'history' && data.scope !== 'activity'
                  && (
                    <Tooltip
                      title={`${t_i18n('Files contained in')} ${t_i18n('Data')}/${t_i18n('Import')}`}
                    >
                      <InformationOutline
                        fontSize="small"
                        color="primary"
                        sx={{ ml: 1 }}
                      />
                    </Tooltip>
                  )
                }
              </BodyItem>
            )}
          </div>
        )}
      />
    </ListItem>
  );
};

export const RetentionLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: '50px' }}
      divider={true}
      secondaryAction={<MoreVert />}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.max_retention.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>

            <BodyItem
              style={{ width: dataColumns.last_execution_date.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="20%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.remaining_count.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="20%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.scope.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="70%"
                height="100%"
              />
            </BodyItem>
            {dataColumns.active && (
              <BodyItem
                style={{ width: dataColumns.active.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="70%"
                  height="100%"
                />
              </BodyItem>
            )}
            <BodyItem
              style={{ width: dataColumns.filters.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="70%"
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};
