import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { EventLine_node$key } from '@components/entities/events/__generated__/EventLine_node.graphql';
import { DraftChip } from '@components/common/draft/DraftChip';
import { ListItemButton } from '@mui/material';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface EventLineProps {
  node: EventLine_node$key;
  dataColumns: DataColumns;
}

const eventLineFragment = graphql`
    fragment EventLine_node on Event {
        id
        name
        event_types
        created
        modified
        start_time
        stop_time
        draftVersion {
            draft_id
            draft_operation
        }
        objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
        }
    }
`;

export const EventLine: FunctionComponent<EventLineProps> = ({
  dataColumns,
  node,
}) => {
  const { fd } = useFormatter();
  const data = useFragment(eventLineFragment, node);
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/entities/events/${data.id}`}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type="Event" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
              {data.draftVersion && (<DraftChip />)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.event_types.width }}
            >
              <FieldOrEmpty source={data.event_types}>{data.event_types?.join(', ')}</FieldOrEmpty>
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.start_time.width }}
            >
              {fd(data.start_time)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.stop_time.width }}
            >
              {fd(data.stop_time)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              {fd(data.created)}
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const EventLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
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
              style={{ width: dataColumns.event_types.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.start_time.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.stop_time.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
