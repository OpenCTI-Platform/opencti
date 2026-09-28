import React from 'react';
import { Box, ListItem, ListItemButton } from '@mui/material';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { useTheme } from '@mui/styles';
import { Link } from 'react-router';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import ItemIcon from '../ItemIcon';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { useComputeLink } from '../../utils/hooks/useAppData';

interface WidgetDistributionListProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[];
  hasSettingAccess?: boolean;
  overflow?: string;
  publicWidget?: boolean;
  /**
   * Resolves the list reproducing the count of row `index`, or null when it
   * cannot be reproduced exactly. A callback rather than a parallel array, so it
   * cannot fall out of step with the rows it describes.
   *
   * Public containers never pass it, which is what keeps public dashboards out.
   */
  getDrilldownLink?: (index: number) => string | null;
}

const WidgetDistributionList = ({
  data,
  hasSettingAccess = false,
  overflow = 'auto',
  publicWidget = false,
  getDrilldownLink,
}: WidgetDistributionListProps) => {
  const theme = useTheme<Theme>();
  const { n } = useFormatter();
  const computeLink = useComputeLink();

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

          let link: string | undefined;
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
            link = entry.id && entry.label !== 'Restricted' ? computeLink(node) : undefined;
          }
          let linkProps = {};
          if (link) {
            linkProps = {
              component: Link,
              to: link,
            };
          }
          const cursorStyle = link ? 'pointer' : 'default';
          const hoverStyle = !link ? { '&.MuiListItemButton-root:hover': { backgroundColor: 'transparent' } } : {};

          const countStyle = {
            marginRight: '20px',
            fontSize: 18,
            fontWeight: 600,
            color: theme.palette.primary.main,
          };
          const drilldownLink = getDrilldownLink?.(key) ?? null;

          return (
            // The row and its count are two distinct destinations, so the count
            // is a sibling of the row link: an anchor cannot contain an anchor.
            <ListItem
              key={entry.id ?? entry.label}
              className="noDrag"
              disablePadding
              divider={true}
              sx={{ height: 50, minHeight: 50, maxHeight: 50 }}
              style={overflow === 'hidden' && key === data.length - 1 ? { borderBottom: 0 } : {}}
            >
              <ListItemButton
                dense={true}
                disableRipple={publicWidget || !link}
                {...linkProps}
                sx={{
                  flex: 1,
                  // Lets the label ellipsis kick in instead of pushing the count out.
                  minWidth: 0,
                  height: '100%',
                  paddingRight: 0,
                  cursor: cursorStyle,
                  ...hoverStyle,
                }}
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
                  primary={(
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
                  )}
                />
              </ListItemButton>
              {drilldownLink ? (
                <Box
                  component={Link}
                  to={drilldownLink}
                  className="noDrag"
                  data-testid="widget-distribution-count"
                  sx={{
                    ...countStyle,
                    textDecoration: 'none',
                    '&:hover': { textDecoration: 'underline' },
                  }}
                >
                  {n(entry.value)}
                </Box>
              ) : (
                <div style={countStyle} data-testid="widget-distribution-count">
                  {n(entry.value)}
                </div>
              )}
            </ListItem>
          );
        })}
      </List>
    </div>
  );
};

export default WidgetDistributionList;
