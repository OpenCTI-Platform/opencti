import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ListItemButton } from '@mui/material';
import ItemIcon from '../ItemIcon';
import { computeLink } from '../../utils/Entity';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';

interface WidgetDistributionListProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  hasSettingAccess?: boolean
  overflow?: string
  publicWidget?: boolean
}

const WidgetDistributionList = ({
  data,
  hasSettingAccess = false,
  overflow = 'auto',
  publicWidget = false,
}: WidgetDistributionListProps) => {
  const theme = useTheme<Theme>();
  const { n } = useFormatter();

  return (
    <div
      id="container"
      style={{
        width: '100%',
        height: '100%',
        paddingBottom: 10,
        marginBottom: 10,
        overflow,
      }}
    >
      <List style={{ marginTop: -10 }}>
        {data.map((entry, key) => {
          const label = getMainRepresentative(entry.entity) || entry.label;

          let link: string | null = null;
          if (!publicWidget && (entry.type !== 'User' || hasSettingAccess)) {
            const node: {
              id: string;
              entity_type: string;
              relationship_type?: string;
              from?: { entity_type: string; id: string };
            } = {
              id: entry.id,
              entity_type: entry.type,
            };
            link = entry.id && entry.label !== 'Restricted' ? computeLink(node) : null;
          }
          let linkProps = {};
          if (link) {
            linkProps = {
              component: Link,
              to: link,
            };
          }

          return (
            <ListItemButton
              key={entry.id ?? entry.label}
              dense={true}
              divider={true}
              disableRipple={publicWidget}
              {...linkProps}
              sx={{
                height: 50,
                minHeight: 50,
                maxHeight: 50,
                paddingRight: 0,
              }}
              style={overflow === 'hidden' && key === data.length - 1 ? { borderBottom: 0 } : {}}
            >
              <ListItemIcon>
                <ItemIcon
                  color={
                    theme.palette.mode === 'light'
                    && entry.color === '#ffffff'
                      ? '#000000'
                      : entry.color
                  }
                  type={entry.id ? entry.type : 'default'}
                />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div
                    style={{
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      paddingRight: 10,
                    }}
                  >
                    {label}
                  </div>
                }
              />
              <div
                style={{
                  float: 'right',
                  marginRight: 20,
                  fontSize: 18,
                  fontWeight: 600,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  color: theme.palette.primary.main,
                }}
              >
                {n(entry.value)}
              </div>
            </ListItemButton>
          );
        })}
      </List>
    </div>
  );
};

export default WidgetDistributionList;
