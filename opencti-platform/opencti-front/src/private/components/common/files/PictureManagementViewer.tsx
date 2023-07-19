import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { graphql, useFragment } from 'react-relay';
import List from '@mui/material/List';
import { useFormatter } from '../../../../components/i18n';
import {
  PictureManagementViewer_pictureManagement$data,
  PictureManagementViewer_pictureManagement$key,
} from './__generated__/PictureManagementViewer_pictureManagement.graphql';

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
  fragment PictureManagementViewer_pictureManagement on StixDomainObject {
    id
    entity_type
    images: x_opencti_files(prefixMimeType: "image/") {
      id
      name
    }
  }
`;

interface PictureManagementViewerProps {
  pictureManagementData: PictureManagementViewer_pictureManagement$key;
}

const PictureManagementViewer: FunctionComponent<PictureManagementViewerProps> = ({ pictureManagementData }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const data: PictureManagementViewer_pictureManagement$data = useFragment(
    pictureManagementViewerFragment,
    pictureManagementData,
  );

  return (
    <Grid item={true} xs={6} style={{ marginTop: 40 }}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Pictures Management')}
        </Typography>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {data.images && data.images.length > 0 ? (
            <List></List>
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
