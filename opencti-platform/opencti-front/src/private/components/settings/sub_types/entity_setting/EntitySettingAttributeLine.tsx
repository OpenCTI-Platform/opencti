import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItemText from '@mui/material/ListItemText/ListItemText';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton, ListItemSecondaryAction } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { NorthEastOutlined, ShortTextOutlined } from '@mui/icons-material';
import { DataColumns } from '../../../../../components/list_lines';
import { Theme } from '../../../../../components/Theme';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import EntitySettingAttributeEdition from './EntitySettingAttributeEdition';
import { EntitySettingAttributeLine_attribute$key } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

const entitySettingAttributeLineFragment = graphql`
  fragment EntitySettingAttributeLine_attribute on TypeAttribute {
    name
    type
    label
    multiple
    mandatory
    mandatoryType
    defaultValues {
      id
      name
    }
    scale
  }
`;

interface EntitySettingAttributeLineProps {
  node?: EntitySettingAttributeLine_attribute$key;
  dataColumns?: DataColumns;
  entitySetting: EntitySettingAttributes_entitySetting$data;
}

const EntitySettingAttributeLine: FunctionComponent<EntitySettingAttributeLineProps> = ({ node = null, dataColumns, entitySetting }) => {
  const classes = useStyles();
  const attribute = useFragment(entitySettingAttributeLineFragment, node);

  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  if (!node || !attribute) {
    return <ErrorNotFound />;
  }

  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);

  return (
    <>
      <ListItemButton
        key={attribute.name}
        divider={true}
        classes={{ root: classes.item }}
        onClick={handleOpenUpdate}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ShortTextOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              {Object.values(dataColumns ?? {}).map((value) => (
                <div
                  key={value.label}
                  className={classes.bodyItem}
                  style={{ width: value.width }}
                >
                  {value.render?.(attribute)}
                </div>
              ))}
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <NorthEastOutlined />
        </ListItemIcon>
      </ListItemButton>
      <EntitySettingAttributeEdition
        attribute={attribute}
        entitySetting={entitySetting}
        handleClose={handleCloseUpdate}
        open={displayUpdate}
      />
    </>
  );
};

export default EntitySettingAttributeLine;

export const EntitySettingAttributeLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const classes = useStyles();
  return (
    <ListItem divider={true} classes={{ root: classes.item }}>
      <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            {Object.values(dataColumns).map((value) => (
              <div
                key={value.label}
                className={classes.bodyItem}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </div>
            ))}
          </div>
        }
      />
      <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
        <NorthEastOutlined />
      </ListItemSecondaryAction>
    </ListItem>
  );
};
