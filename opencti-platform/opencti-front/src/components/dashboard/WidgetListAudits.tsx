import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import { useTheme } from '@mui/styles';
import { AuditsListComponentQuery$data } from '../../private/components/common/audits/__generated__/AuditsListComponentQuery.graphql';
import MarkdownDisplay from '../MarkdownDisplay';
import ItemIcon from '../ItemIcon';
import { resolveLink } from '../../utils/Entity';
import { useGenerateAuditMessage } from '../../utils/history';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';

interface WidgetListAuditsProps {
  data: NonNullable<AuditsListComponentQuery$data['audits']>['edges']
}

const WidgetListAudits = ({ data }: WidgetListAuditsProps) => {
  const theme = useTheme<Theme>();
  const { fldt } = useFormatter();

  const bodyItemStyle: React.CSSProperties = {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  };

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
              audit.context_data?.entity_type === 'Workspace' && audit.context_data?.workspace_type
                ? audit.context_data.workspace_type
                : audit.context_data.entity_type,
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
              component={link ? Link : 'div'}
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
};

export default WidgetListAudits;
