import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsListContentQuery } from '@components/common/audits/__generated__/AuditsListContentQuery.graphql';
import { useGenerateAuditMessage } from '../../../../utils/history';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

export const auditsListContentQuery = graphql`
  query AuditsListContentQuery(
    $types: [String!]
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    audits(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          event_status
          event_type
          event_scope
          timestamp
          user {
            id
            entity_type
            name
          }
          context_data {
            entity_id
            entity_type
            entity_name
            message
            workspace_type
          }
        }
      }
    }
  }
`;

interface AuditsListContentProps {
  queryRef: PreloadedQuery<AuditsListContentQuery>,
}

const AuditsListContent: FunctionComponent<AuditsListContentProps> = ({
  queryRef,
}) => {
  const bodyItemStyle = {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  };
  const theme = useTheme<Theme>();
  const queryData = usePreloadedQuery<AuditsListContentQuery>(auditsListContentQuery, queryRef);
  const { fldt } = useFormatter();

  if (queryData && queryData.audits?.edges && queryData.audits.edges.length > 0) {
    const data = queryData.audits.edges;
    return (
      <div id="container" style={{
        width: '100%',
        height: '100%',
        overflow: 'auto',
        paddingBottom: 10,
        marginBottom: 10,
      }}
      >
        <List style={{ marginTop: -10 }}>
          {data.map((auditEdge) => {
            const audit = auditEdge.node;
            const color = audit.event_status === 'error'
              ? theme.palette.error.main
              : undefined;
            const message = useGenerateAuditMessage(audit);
            const link = audit.context_data?.entity_type
              ? `${resolveLink(
                audit.context_data?.entity_type === 'Workspace'
                  ? audit.context_data?.workspace_type
                  : audit.context_data?.entity_type,
              )}/${audit.context_data?.entity_id}`
              : undefined;
            return (
              <ListItemButton
                key={audit.id}
                dense={true}
                className="noDrag"
                style={{
                  height: 50,
                  minHeight: 50,
                  maxHeight: 50,
                  paddingRight: 0,
                }}
                divider={true}
                component={link ? Link : undefined}
                to={link}
              >
                <ListItemIcon>
                  <ItemIcon
                    color={color}
                    type={
                      audit.context_data?.entity_type
                      ?? audit.event_type
                    }
                  />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <>
                      <div
                        style={{ ...bodyItemStyle, width: '15%' }}
                      >
                        <span style={{ color }}>
                          {fldt(audit.timestamp)}
                        </span>
                      </div>
                      <div
                        style={{ ...bodyItemStyle, width: '18%' }}
                      >
                        {audit.user?.name ?? '-'}
                      </div>
                      <div
                        style={{ ...bodyItemStyle, width: '15%' }}
                      >
                        {audit.event_scope}
                      </div>
                      <div
                        style={{ ...bodyItemStyle, width: '22%' }}
                      >
                        {audit.context_data?.entity_name
                          ?? audit.event_type}
                      </div>
                      <div
                        style={{ ...bodyItemStyle, width: '30%' }}
                      >
                        <span style={{ color }}>
                          <MarkdownDisplay
                            content={message}
                            remarkGfmPlugin={true}
                            commonmark={true}
                          />
                        </span>
                      </div>
                    </>
                  }
                />
              </ListItemButton>
            );
          })}
        </List>
      </div>
    );
  }
  return <WidgetNoData />;
};

export default AuditsListContent;
