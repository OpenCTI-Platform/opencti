import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';

interface SubTypeLineProps {
  subTypeId: string
  subTypeLabel: string
  dataColumns: DataColumns
}

const SubTypeLine: FunctionComponent<SubTypeLineProps> = ({
  subTypeId,
  subTypeLabel,
  dataColumns,
}) => {
  return (
    <ListItemButton
      key={subTypeId}
      divider={true}
      component={Link}
      to={`/dashboard/settings/entity_types/${subTypeId}`}>
      <ListItemIcon>
        <ItemIcon type={subTypeId} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div style={{ width: dataColumns.entity_type.width }}>
            <div>{subTypeLabel}</div>
          </div>
        }
      />
      <ListItemIcon>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export default SubTypeLine;

export const SubTypeLineDummy = ({ dataColumns } : { dataColumns: DataColumns }) => {
  return (
    <ListItem divider={true}>
      <ListItemIcon>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div style={{ width: dataColumns.entity_type.width }}>
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              height="100%"
            />
          </div>
        }
      />
      <ListItemIcon>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
