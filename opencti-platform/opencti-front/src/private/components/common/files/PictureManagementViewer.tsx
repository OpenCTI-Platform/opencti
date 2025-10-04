import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import PictureLine from './PictureLine';
import { PictureManagementViewer_entity$data, PictureManagementViewer_entity$key } from './__generated__/PictureManagementViewer_entity.graphql';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import { Grid, List, Paper, Typography } from '@components';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
}));

export const pictureManagementViewerFragment = graphql`
  fragment PictureManagementViewer_entity on StixDomainObject {
    id
    entity_type
    images: importFiles(prefixMimeType: "image/") {
      edges {
        node {
          id
          name
          ...PictureManagementUtils_node
        }
      }
    }
  }
`;

interface PictureManagementViewerProps {
  entity: PictureManagementViewer_entity$key;
}

const PictureManagementViewer: FunctionComponent<
PictureManagementViewerProps
> = ({ entity }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

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
  const images = data?.images?.edges
    ?.filter((edge) => edge?.node)
    .map((edge) => edge?.node) ?? [];
  return (
    <Grid size={6}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t_i18n('Pictures Management')}
        </Typography>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {images && images.length > 0 ? (
            <>
              <ColumnsLinesTitles
                dataColumns={dataColumns}
                handleSort={() => {}}
              />
              <List>
                {images.map(
                  (file, idx) => file && (
                  <PictureLine
                    picture={file}
                    key={idx}
                    dataColumns={dataColumns}
                    entityId={data.id}
                  />
                  ),
                )}
              </List>
            </>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t_i18n('No file for the moment')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    </Grid>
  );
};

export default PictureManagementViewer;
