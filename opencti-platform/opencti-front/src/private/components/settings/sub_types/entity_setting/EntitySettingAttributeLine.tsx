import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { LockPersonOutlined, NorthEastOutlined, ShortTextOutlined } from '@mui/icons-material';
import EEChip from '@components/common/entreprise_edition/EEChip';
import Box from '@mui/material/Box';
import { DataColumns } from '../../../../../components/list_lines';
import type { Theme } from '../../../../../components/Theme';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import EntitySettingAttributeEdition from './EntitySettingAttributeEdition';
import { EntitySettingAttributeLine_attribute$key } from './__generated__/EntitySettingAttributeLine_attribute.graphql';
import { EntitySettingAttributes_entitySetting$data } from './__generated__/EntitySettingAttributes_entitySetting.graphql';
import { INPUT_AUTHORIZED_MEMBERS } from '../../../../../utils/authorizedMembers';
import useEnterpriseEdition from '../../../../../utils/hooks/useEnterpriseEdition';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    editDefault
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
  const isEnterpriseEdition = useEnterpriseEdition();
  const attribute = useFragment(entitySettingAttributeLineFragment, node);

  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  if (!node || !attribute) {
    return <ErrorNotFound />;
  }

  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);

  const needEE = attribute.name === INPUT_AUTHORIZED_MEMBERS && !isEnterpriseEdition;
  const nothingToUpdate = attribute.mandatoryType !== 'customizable' && !attribute.editDefault;

  return (
    <>
      <ListItemButton
        key={attribute.name}
        divider={true}
        classes={{ root: classes.item }}
        onClick={() => !needEE && !nothingToUpdate && handleOpenUpdate()}
        disableRipple={needEE || nothingToUpdate}
        sx={needEE || nothingToUpdate
          ? {
            '&:hover': {
              cursor: 'default',
              backgroundColor: 'transparent',
            },
          }
          : {}
        }
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          {attribute.name === INPUT_AUTHORIZED_MEMBERS
            ? <LockPersonOutlined
                fontSize="small"
                color={!needEE ? 'warning' : 'ee'}
              />
            : <ShortTextOutlined />
          }
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              {Object.values(dataColumns ?? {}).map((value, i) => (
                <div
                  key={value.label}
                  className={classes.bodyItem}
                  style={{ width: value.width }}
                >
                  {value.render?.(attribute)}
                  {needEE && i === 0 && <EEChip />}
                </div>
              ))}
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          {!needEE && !nothingToUpdate && <NorthEastOutlined />}
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
    <ListItem
      divider={true}
      classes={{ root: classes.item }}
      secondaryAction={
        <Box sx={{ root: classes.itemIconDisabled }}>
          <NorthEastOutlined />
        </Box>
      }
    >
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
    </ListItem>
  );
};
