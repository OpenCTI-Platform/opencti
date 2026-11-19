import React, { FunctionComponent, useState } from 'react';
import { styled, useTheme } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { DataColumns } from '../../../../../components/list_lines';
import { AuditLine_node$key } from './__generated__/AuditLine_node.graphql';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import ItemIcon from '../../../../../components/ItemIcon';
import { useGenerateAuditMessage } from '../../../../../utils/history';
import { HandleAddFilter } from '../../../../../utils/hooks/useLocalStorage';
import AuditDrawer from './AuditDrawer';
import { EMPTY_VALUE } from '../../../../../utils/String';
import MarkdownDisplay from '../../../../../components/markdownDisplay/MarkdownDisplay';
import { bodyItemStyle } from '../../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface AuditLineProps {
  node: AuditLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
}

const AuditLineFragment = graphql`
  fragment AuditLine_node on Log {
    id
    entity_type
    event_type
    event_scope
    event_status
    timestamp
    context_uri
    user {
      id
      name
    }
    context_data {
      entity_id
      entity_type
      entity_name
      message
      from_id
      to_id
    }
  }
`;

export const AuditLine: FunctionComponent<AuditLineProps> = ({
  dataColumns,
  node,
}) => {
  const { ftdt } = useFormatter();
  const theme = useTheme<Theme>();
  const [selectedLog, setSelectedLog] = useState<string | null>(null);
  const data = useFragment(AuditLineFragment, node);
  const message = useGenerateAuditMessage(data);
  const color = data.event_status === 'error' ? theme.palette.error.main : undefined;

  return (
    <>
      {selectedLog && (
        <AuditDrawer
          open={!!selectedLog}
          logId={selectedLog}
          onClose={() => setSelectedLog(null)}
        />
      )}
      <ListItemButton
        sx={{ paddingLeft: '10px', height: 50 }}
        divider={true}
        onClick={() => setSelectedLog(data.id)}
      >
        <ListItemIcon sx={{ color: theme.palette.primary.main }}>
          <ItemIcon
            color={color}
            type={data.context_data?.entity_type ?? data.event_scope}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
            <div>
              <BodyItem
                style={{ width: dataColumns.timestamp.width }}
              >
                {ftdt(data.timestamp, 'numeric')}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.user.width }}
              >
                {data.user?.name ?? EMPTY_VALUE}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.event_type.width }}
              >
                {data.event_type}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.event_scope.width }}
              >
                {data.event_scope ?? EMPTY_VALUE}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.message.width }}
              >
                <span style={{ color }}>
                  <MarkdownDisplay
                    content={`\`${data.user?.name}\` ${message}`}
                    remarkGfmPlugin={true}
                    commonmark={true}
                  />
                </span>
              </BodyItem>
            </div>
          )}
        />
      </ListItemButton>
    </>
  );
};

export const AuditLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
      <ListItemIcon sx={{ color: 'grey.700' }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.timestamp.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.user.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.event_type.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.event_scope.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.message.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};
