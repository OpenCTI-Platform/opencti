import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Skeleton from '@mui/material/Skeleton';
import ListItemText from '@mui/material/ListItemText';
import { MoreVertOutlined } from '@mui/icons-material';
import React from 'react';
import { styled } from '@mui/material/styles';
import { DataColumns } from '../../../components/list_lines';
import { bodyItemStyle } from '../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const LineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={<MoreVertOutlined />}
    >
      <ListItemIcon sx={{ color: 'grey.700' }}>
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

export default LineDummy;
