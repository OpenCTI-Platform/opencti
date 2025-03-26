import { useFragment } from 'react-relay';
import { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { React } from 'mdi-material-ui';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { NorthEastOutlined } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { ListItemButton } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import { getFileUri } from '../../../../utils/utils';
import { DataColumns } from '../../../../components/list_lines';
import PictureManagementEdition from './PictureManagementEdition';
import { pictureManagementUtilsFragment } from './PictureManagementUtils';
import { PictureManagementUtils_node$key } from './__generated__/PictureManagementUtils_node.graphql';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';

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
    display: 'flex',
    alignItems: 'center',
    height: 40,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
}));

interface PictureLineComponentProps {
  picture: PictureManagementUtils_node$key;
  dataColumns: DataColumns;
  entityId: string;
}

const PictureLine: FunctionComponent<PictureLineComponentProps> = ({
  picture,
  dataColumns,
  entityId,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const data = useFragment(pictureManagementUtilsFragment, picture);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);
  return (
    <>
      <ListItemButton
        classes={{ root: classes.item }}
        divider={true}
        onClick={handleOpenUpdate}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <img
            style={{ height: 33, width: 33, borderRadius: 4 }}
            src={getFileUri(data.id)}
            alt={data.name}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.description.width }}
              >
                {data.metaData?.description}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.order.width }}
              >
                {data.metaData?.order}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.inCarousel.width }}
              >
                <ItemBoolean
                  status={data.metaData?.inCarousel === true}
                  label={data.metaData?.inCarousel ? t_i18n('Yes') : t_i18n('No')}
                />
              </div>
            </>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <NorthEastOutlined fontSize="small" />
        </ListItemIcon>
      </ListItemButton>
      <Drawer
        open={displayUpdate}
        title={t_i18n('Update a picture')}
        onClose={handleCloseUpdate}
      >
        <PictureManagementEdition
          entityId={entityId}
          handleClose={handleCloseUpdate}
          picture={data}
        />
      </Drawer>
    </>
  );
};

export default PictureLine;
