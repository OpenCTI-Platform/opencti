import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import React, { CSSProperties } from 'react';
import { useTheme } from '@mui/styles';
import { ListItemButton } from '@mui/material';
import ItemIcon from '../ItemIcon';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import ItemMarkings from '../ItemMarkings';
import { computeLink } from '../../utils/Entity';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';

const bodyItemStyle = (width: string): CSSProperties => ({
  height: 20,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 2,
  width,
});

interface WidgetListRelationshipsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  dateAttribute: string
  publicWidget?: boolean
}

const WidgetListRelationships = ({
  data,
  dateAttribute,
  publicWidget = false,
}: WidgetListRelationshipsProps) => {
  const theme = useTheme<Theme>();
  const { fsd, t_i18n } = useFormatter();

  return (
    <div
      id="container"
      style={{
        width: '100%',
        height: '100%',
        overflow: 'auto',
        paddingBottom: 10,
        marginBottom: 10,
      }}
    >
      <List style={{ minWidth: 800, marginTop: -10 }}>
        {data.map((stixRelationshipEdge) => {
          const stixRelationship = stixRelationshipEdge.node;
          const remoteNode = stixRelationship.from
            ? stixRelationship.from
            : stixRelationship.to;
          let link = null;
          if (!publicWidget && remoteNode) {
            link = computeLink(remoteNode);
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
              key={stixRelationship.id}
              dense={true}
              className="noDrag"
              divider={true}
              disableRipple={publicWidget}
              {...linkProps}
              style={{
                height: 50,
                minHeight: 50,
                maxHeight: 50,
                paddingRight: 0,
              }}
            >
              <ListItemIcon
                style={{
                  marginRight: 0,
                  color: theme.palette.primary.main,
                }}
              >
                <ItemIcon
                  type={stixRelationship.entity_type}
                  color="primary"
                />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <div style={bodyItemStyle('10%')}>
                      <ItemIcon
                        type={
                          stixRelationship.from
                          && stixRelationship.from.entity_type
                        }
                        variant="inline"
                      />
                      {/* eslint-disable-next-line no-nested-ternary */}
                      {stixRelationship.from
                        ? stixRelationship.from.relationship_type
                          ? t_i18n(
                            `relationship_${stixRelationship.from.entity_type}`,
                          )
                          : t_i18n(
                            `entity_${stixRelationship.from.entity_type}`,
                          )
                        : t_i18n('Restricted')}
                    </div>
                    <div style={bodyItemStyle('18%')}>
                      <code>
                        {stixRelationship.from
                          ? getMainRepresentative(stixRelationship.from)
                          : t_i18n('Restricted')}
                      </code>
                    </div>
                    <div style={bodyItemStyle('10%')}>
                      <i>
                        {t_i18n(
                          `relationship_${stixRelationship.relationship_type}`,
                        )}
                      </i>
                    </div>
                    <div style={bodyItemStyle('10%')}>
                      <ItemIcon
                        type={
                          stixRelationship.to
                          && stixRelationship.to.entity_type
                        }
                        variant="inline"
                      />
                      {/* eslint-disable-next-line no-nested-ternary */}
                      {stixRelationship.to
                        ? stixRelationship.to.relationship_type
                          ? t_i18n(
                            `relationship_${stixRelationship.to.entity_type}`,
                          )
                          : t_i18n(
                            `entity_${stixRelationship.to.entity_type}`,
                          )
                        : t_i18n('Restricted')}
                    </div>
                    <div style={bodyItemStyle('18%')}>
                      <code>
                        {stixRelationship.to
                          ? getMainRepresentative(stixRelationship.to)
                          : t_i18n('Restricted')}
                      </code>
                    </div>
                    <div style={bodyItemStyle('10%')}>
                      {fsd(stixRelationship[dateAttribute])}
                    </div>
                    <div style={bodyItemStyle('12%')}>
                      {R.pathOr(
                        '',
                        ['createdBy', 'name'],
                        stixRelationship,
                      )}
                    </div>
                    <div style={bodyItemStyle('10%')}>
                      <ItemMarkings
                        variant="inList"
                        markingDefinitions={
                          stixRelationship.objectMarking ?? []
                        }
                        limit={1}
                      />
                    </div>
                  </div>
                }
              />
            </ListItemButton>
          );
        })}
      </List>
    </div>
  );
};

export default WidgetListRelationships;
