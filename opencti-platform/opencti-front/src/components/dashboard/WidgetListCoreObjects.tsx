import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import React, { CSSProperties } from 'react';
import { resolveLink } from '../../utils/Entity';
import ItemIcon from '../ItemIcon';
import { getMainRepresentative } from '../../utils/defaultRepresentatives';
import ItemStatus from '../ItemStatus';
import ItemMarkings from '../ItemMarkings';
import { useFormatter } from '../i18n';

const bodyItemStyle = (width: string): CSSProperties => ({
  height: 20,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
  width,
});

interface WidgetListCoreObjectsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  dateAttribute: string
  publicWidget?: boolean
}

const WidgetListCoreObjects = ({
  data,
  dateAttribute,
  publicWidget = false,
}: WidgetListCoreObjectsProps) => {
  const { fsd } = useFormatter();

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
      <List style={{ marginTop: -10 }}>
        {data.map((stixCoreObjectEdge) => {
          const stixCoreObject = stixCoreObjectEdge.node;
          const date = stixCoreObject[dateAttribute];

          const link = publicWidget ? null : `${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`;
          let linkProps = {};
          if (link) {
            linkProps = {
              component: Link,
              to: link,
            };
          }

          return (
            <ListItem
              key={stixCoreObject.id}
              className="noDrag"
              divider={true}
              disableRipple={publicWidget}
              button={true}
              {...linkProps}
              sx={{
                paddingLeft: '10px',
                height: 50,
              }}
            >
              <ListItemIcon>
                <ItemIcon type={stixCoreObject.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <>
                    <div style={bodyItemStyle('30%')}>
                      {getMainRepresentative(stixCoreObject)}
                    </div>
                    <div style={bodyItemStyle('10%')}>
                      {fsd(date)}
                    </div>
                    <div style={bodyItemStyle('15%')}>
                      {R.pathOr(
                        '',
                        ['createdBy', 'name'],
                        stixCoreObject,
                      )}
                    </div>
                    <div style={bodyItemStyle('15%')}>
                      <StixCoreObjectLabels
                        variant="inList"
                        labels={stixCoreObject.objectLabel}
                      />
                    </div>
                    <div style={bodyItemStyle('15%')}>
                      <ItemStatus
                        status={stixCoreObject.status}
                        variant="inList"
                        disabled={!stixCoreObject.workflowEnabled}
                      />
                    </div>
                    <div style={bodyItemStyle('15%')}>
                      <ItemMarkings
                        variant="inList"
                        markingDefinitions={stixCoreObject.objectMarking ?? []}
                        limit={1}
                      />
                    </div>
                  </>
                }
              />
            </ListItem>
          );
        })}
      </List>
    </div>
  );
};

export default WidgetListCoreObjects;
