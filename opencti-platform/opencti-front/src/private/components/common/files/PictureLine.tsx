import { useFragment } from 'react-relay';
import { FunctionComponent, useState } from 'react';
import { styled } from '@mui/material/styles';
import { React } from 'mdi-material-ui';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { NorthEastOutlined } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { ListItemButton } from '@mui/material';
import { getFileUri } from '../../../../utils/utils';
import { DataColumns } from '../../../../components/list_lines';
import PictureManagementEdition from './PictureManagementEdition';
import { pictureManagementUtilsFragment } from './PictureManagementUtils';
import { PictureManagementUtils_node$key } from './__generated__/PictureManagementUtils_node.graphql';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';

const BodyItem = styled('div')({
  display: 'flex',
  alignItems: 'center',
  height: 40,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
});

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
  const { t_i18n } = useFormatter();
  const data = useFragment(pictureManagementUtilsFragment, picture);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);
  return (
    <>
      <ListItemButton
        sx={{ paddingLeft: '10px', height: 50 }}
        divider={true}
        onClick={handleOpenUpdate}
      >
        <ListItemIcon sx={{ color: 'primary.main' }}>
          <img
            style={{ height: 33, width: 33, borderRadius: 4 }}
            src={getFileUri(data.id)}
            alt={data.name}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <BodyItem
                style={{ width: dataColumns.description.width }}
              >
                {data.metaData?.description}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.order.width }}
              >
                {data.metaData?.order}
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.inCarousel.width }}
              >
                <ItemBoolean
                  status={data.metaData?.inCarousel === true}
                  label={data.metaData?.inCarousel ? t_i18n('Yes') : t_i18n('No')}
                />
              </BodyItem>
            </>
          )}
        />
        <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
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
