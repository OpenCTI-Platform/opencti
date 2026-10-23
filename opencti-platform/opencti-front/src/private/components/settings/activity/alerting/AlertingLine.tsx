import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { BackupTableOutlined, CampaignOutlined, MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { graphql, useFragment } from 'react-relay';
import { Theme } from '../../../../../components/Theme';
import Box from '@mui/material/Box';
import IconButton from '@common/button/IconButton';
import { DataColumns } from '../../../../../components/list_lines';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import { dayStartDate } from '../../../../../utils/Time';
import { AlertingLine_node$key } from './__generated__/AlertingLine_node.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import AlertingPopover from './AlertingPopover';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../../utils/filters/filtersUtils';
import { EMPTY_VALUE } from '../../../../../utils/String';
import { HandleAddFilter } from '../../../../../utils/hooks/useLocalStorage';
import Tag from '@common/tag/Tag';
import NotifierChips from '@components/profile/triggers/NotifierChips';
import { styled, useTheme } from '@mui/material/styles';
import { Stack } from '@mui/material';
import { bodyItemStyle } from '../../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface AlertingLineProps {
  node: AlertingLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions?: AlertingPaginationQuery$variables;
}

const alertingLineFragment = graphql`
    fragment AlertingLine_node on Trigger {
        id
        name
        trigger_type
        description
        filters
        created
        modified
        notifiers {
            id
            name
        }
        period
        trigger_time
        triggers {
            id
            name
        }
    }
`;

export const AlertingLineComponent: FunctionComponent<AlertingLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n, nt } = useFormatter();
  const data = useFragment(alertingLineFragment, node);
  const filters = deserializeFilterGroupForFrontend(data.filters);
  const currentTime = data.trigger_time?.split('-') ?? [
    dayStartDate().toISOString(),
  ];
  const day = currentTime.length > 1 ? currentTime[0] : '1';
  const time = currentTime.length > 1
    ? new Date(`2000-01-01T${currentTime[1]}`)
    : new Date(`2000-01-01T${currentTime[0]}`);
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
      <ListItemIcon>
        {data.trigger_type === 'live' ? (
          <CampaignOutlined color="warning" />
        ) : (
          <BackupTableOutlined color="secondary" />
        )}
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.trigger_type.width }}
            >
              <Tag
                color={data.trigger_type === 'live' ? theme.palette.severity.high : theme.palette.severity.low}
                label={
                  data.trigger_type === 'live'
                    ? t_i18n('Live trigger')
                    : t_i18n('Regular digest')
                }
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.notifiers.width }}
            >
              <NotifierChips notifiers={data.notifiers} />
            </BodyItem>
            {data.trigger_type === 'live' && (
              isFilterGroupNotEmpty(filters)
                ? (
                    <FilterIconButton
                      filters={filters}
                      variant="small"
                      redirection
                      showGroupsSummaryButtonOnReadOnly
                    />
                  )
                : (
                    <BodyItem
                      style={{ width: dataColumns.filters.width }}
                    >
                      {EMPTY_VALUE}
                    </BodyItem>
                  )
            )}
            {data.trigger_type === 'digest' && (
              <Stack
                direction="row"
                sx={{
                  gap: 1,
                  flexWrap: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                <Tag
                  label={`${t_i18n('Period: ')}${data.period}`}
                />
                {currentTime.length > 1 && (
                  <Tag
                    label={`${t_i18n('Day: ')}${day}`}
                  />
                )}
                {data.trigger_time && data.trigger_time.length > 0 && (
                  <Tag
                    label={`${t_i18n('Time: ')}${nt(time)}`}
                  />
                )}
              </Stack>
            )}
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <AlertingPopover data={data} paginationOptions={paginationOptions} />
      </ListItemIcon>
    </ListItem>
  );
};

export const AlertingLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const { t_i18n } = useFormatter();
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <Box>
          <IconButton aria-label={t_i18n('Open menu')} disabled={true}>
            <MoreVert />
          </IconButton>
        </Box>
      )}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
