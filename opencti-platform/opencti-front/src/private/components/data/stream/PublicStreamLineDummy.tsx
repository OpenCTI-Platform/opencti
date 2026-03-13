import React, { CSSProperties } from 'react';
import { useTheme } from '@mui/material/styles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';

const bodyItemStyle: CSSProperties = {
  height: 40,
  display: 'flex',
  alignItems: 'center',
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
};

interface PublicStreamLineDummyProps {
  dataColumns: DataColumns;
}

const PublicStreamLineDummy = ({ dataColumns }: PublicStreamLineDummyProps) => {
  const theme = useTheme<Theme>();
  return (
    <ListItem
      style={{ paddingLeft: 10, height: 50 }}
      divider={true}
      secondaryAction={<MoreVert style={{ color: theme.palette.grey?.[700] }} />}
    >
      <ListItemIcon style={{ color: theme.palette.primary.main }}>
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
            <div style={{ ...bodyItemStyle, width: dataColumns.name.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div style={{ ...bodyItemStyle, width: dataColumns.description.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div style={{ ...bodyItemStyle, width: dataColumns.id.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div style={{ ...bodyItemStyle, width: dataColumns.stream_public.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div style={{ ...bodyItemStyle, width: dataColumns.stream_live.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
            <div style={{ ...bodyItemStyle, width: dataColumns.consumers.width }}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="50%"
              />
            </div>
          </div>
        )}
      />
    </ListItem>
  );
};

export default PublicStreamLineDummy;
