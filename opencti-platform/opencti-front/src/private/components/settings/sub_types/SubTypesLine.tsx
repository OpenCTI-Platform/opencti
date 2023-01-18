import React, { FunctionComponent } from 'react';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import Checkbox from '@mui/material/Checkbox';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { SubType_subType$data } from './__generated__/SubType_subType.graphql';

const useStyles = makeStyles(() => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
}));

interface SubTypeLineProps {
  node: SubType_subType$data
  dataColumns: DataColumns
  selectedElements: Record<string, { id: string }>
  deSelectedElements: Record<string, { id: string }>
  selectAll: boolean
  onToggleEntity: (entity: { id: string }) => void
  onToggleShiftEntity: (index: number, entity: { id: string }) => void
  index: number
}

const SubTypeLine: FunctionComponent<SubTypeLineProps> = ({
  node,
  dataColumns,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
  onToggleShiftEntity,
  index,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  return (
    <ListItemButton key={node.id} divider={true} classes={{ root: classes.item }}>
      <ListItemIcon style={{ minWidth: 40 }}
                    onClick={(event) => (event.shiftKey
                      ? onToggleShiftEntity(index, { id: node.id })
                      : onToggleEntity({ id: node.id }))}>
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(node.id in (deSelectedElements || {})))
            || node.id in (selectedElements || {})}
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItem component={Link}
                to={`/dashboard/settings/entity_types/${node.id}`}
                style={{ paddingLeft: 0 }}>
        <ListItemIcon>
          <ItemIcon type={node.id} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div style={{ width: dataColumns.entity_type.width }}>
              <div>{t(`entity_${node.label}`)}</div>
            </div>
          }
        />
        <ListItemIcon>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    </ListItemButton>
  );
};

export default SubTypeLine;

export const SubTypeLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  const classes = useStyles();

  return (
    <ListItem divider={true} classes={{ root: classes.item }}>
      <ListItemIcon style={{ minWidth: 40 }}>
        <Checkbox
          edge="start"
          disabled={true}
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItem style={{ paddingLeft: 0 }}>
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
    </ListItem>
  );
};
