import { useFragment, useMutation } from 'react-relay';
import { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListItem from '@mui/material/ListItem';
import { React } from 'mdi-material-ui';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import IconButton from '@mui/material/IconButton';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { NorthEastOutlined } from '@mui/icons-material';
import Checkbox from '@mui/material/Checkbox';
import Drawer from '@mui/material/Drawer';
import { Theme } from '../../../../components/Theme';
import { getFileUri } from '../../../../utils/utils';
import { DataColumns } from '../../../../components/list_lines';
import PictureManagementEdition from './PictureManagementEdition';
import { pictureManagementUtilsFragment, pictureManagementUtilsMutation } from './PictureManagementUtils';
import { PictureManagementUtils_node$key } from './__generated__/PictureManagementUtils_node.graphql';
import { PictureManagementUtilsMutation } from './__generated__/PictureManagementUtilsMutation.graphql';

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
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

interface PictureLineComponentProps {
  picture: PictureManagementUtils_node$key;
  dataColumns: DataColumns;
  entityId: string;
}

const PictureLine: FunctionComponent<PictureLineComponentProps> = ({ picture, dataColumns, entityId }) => {
  const classes = useStyles();
  const data = useFragment(pictureManagementUtilsFragment, picture);
  const [isInCarousel, setIsInCarousel] = useState(!!data.inCarousel);
  const [commit] = useMutation<PictureManagementUtilsMutation>(pictureManagementUtilsMutation);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleCheckbox = () => {
    const updatedValue = !isInCarousel;
    setIsInCarousel(updatedValue);
    const input = {
      id: data.id,
      description: data.description,
      order: data.order,
      inCarousel: updatedValue,
    };
    commit({
      variables: {
        id: entityId,
        input,
      },
    });
  };

  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);

  return (
    <div>
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={false}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <img
            style={{ height: '33px', width: '33px' }}
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
                {data.description}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.order.width, paddingLeft: '20px', justifyContent: 'center' }}
              >
                {data.order}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.inCarousel.width, paddingLeft: '10px', justifyContent: 'center' }}
              >
                <Checkbox
                  checked={isInCarousel}
                  onClick={handleCheckbox}
                />
              </div>
            </>
          }
        />
        <ListItemSecondaryAction>
          <IconButton
            disabled={false}
            aria-haspopup="true"
            style={{ marginTop: 3 }}
            size="large"
            onClick={handleOpenUpdate}
          >
            <NorthEastOutlined />
          </IconButton>
        </ListItemSecondaryAction>
      </ListItem>
      <Drawer
        open={displayUpdate}
        anchor="right"
        sx={{ zIndex: 1202 }}
        elevation={1}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseUpdate}
      >
        <PictureManagementEdition
          entityId={entityId}
          handleClose={handleCloseUpdate}
          picture={data}
        />
      </Drawer>
    </div>
  );
};

export default PictureLine;
