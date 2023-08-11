import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { graphql, useFragment } from 'react-relay';
import List from '@mui/material/List';
import { useFormatter } from '../../../../components/i18n';
import PictureLine from './PictureLine';
import {
  PictureManagementViewer_entity$data,
  PictureManagementViewer_entity$key,
} from './__generated__/PictureManagementViewer_entity.graphql';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
    marginTop: 2,
  },
}));

const pictureManagementViewerFragment = graphql`
  fragment PictureManagementViewer_entity on StixDomainObject {
    id
    entity_type
    images: x_opencti_files(prefixMimeType: "image/") {
      ...PictureManagementUtils_node
    }
  }
`;

interface PictureManagementViewerProps {
  entity: PictureManagementViewer_entity$key
}

const PictureManagementViewer: FunctionComponent<PictureManagementViewerProps> = ({ entity }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const data: PictureManagementViewer_entity$data = useFragment(
    pictureManagementViewerFragment,
    entity,
  );

  const dataColumns = {
    description: {
      label: 'Description',
      width: '60%',
      isSortable: false,
    },
    order: {
      label: 'Order',
      width: '15%',
      isSortable: false,
    },
    inCarousel: {
      label: 'In Carousel',
      width: '20%',
      isSortable: false,
    },
  };

  const images = data.images ?? [];

  return (
    <Grid item={true} xs={6} style={{ marginTop: 40 }}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Pictures Management')}
        </Typography>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {images && images.length > 0 ? (
            <div>
              <ColumnsLinesTitles
                dataColumns={dataColumns}
                handleSort={() => {}}
              />
              <List>
                {images.map((file, idx) => (
                  <PictureLine picture={file} key={idx} dataColumns={dataColumns} entityId={data.id}/>
                ))}
              </List>
            </div>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No file for the moment')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    </Grid>
  );
};

export default PictureManagementViewer;
