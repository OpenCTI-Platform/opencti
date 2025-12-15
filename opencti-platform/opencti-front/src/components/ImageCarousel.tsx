import React, { FunctionComponent, useState } from 'react';
import Carousel from 'react-material-ui-carousel';
import makeStyles from '@mui/styles/makeStyles';
import { ImageListItem, ImageListItemBar, Modal } from '@mui/material';
import Skeleton from '@mui/material/Skeleton';
import Paper from '@mui/material/Paper';
import IconButton from '@common/button/IconButton';
import { ZoomOutMapOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import { convertImagesToCarousel } from '../utils/edition';
import type { Theme } from './Theme';
import { isNotEmptyField } from '../utils/utils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme: Theme) => ({
  carousel: {
    textAlign: 'center',
    width: '100%',
  },
  indicators: {
    color: theme.palette.background.accent,
    '&:hover': {
      color: theme.palette.primary.main,
    },
    '&:active': {
      color: theme.palette.primary.main,
    },
  },
  activeIndicators: {
    color: theme.palette.secondary.main,
  },
  indicatorsContainer: {
    marginTop: 0,
  },
  navButtons: {
    fontSize: '20px',
    top: 'calc(50% - 15px) !important',
  },
  buttonWrapper: {
    height: 50,
    top: 'calc(50% - 40px)',
    '&:hover': {
      '& $button': {
        backgroundColor: theme.palette.background.accent,
        filter: 'brightness(120%)',
        opacity: '0.4',
      },
    },
  },
}));

interface ImageMetaData {
  description: string | null;
  inCarousel: boolean | null;
  mimetype: string | null;
  order: number | null;
}

export interface ImagesData {
  edges: ReadonlyArray<{
    node: {
      id: string;
      metaData: ImageMetaData | null;
      name: string;
    };
  } | null> | null;
}

interface ImageCarouselProps {
  data: {
    images: ImagesData | null;
  };
}

interface CarouselImage {
  tooltipTitle: string;
  imageSrc: string;
  altText: string;
  id: string;
}

const modalStyle = {
  position: 'fixed',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
};

const ImageCarousel: FunctionComponent<ImageCarouselProps> = ({ data }) => {
  const [currentImage, setCurrentImage] = useState<CarouselImage | null>(null);
  const classes = useStyles();
  const images = convertImagesToCarousel(data);
  return (
    <>
      <Carousel
        className={classes.carousel}
        animation="slide"
        autoPlay={false}
        height={200}
        indicatorIconButtonProps={{ className: classes.indicators }}
        activeIndicatorIconButtonProps={{ className: classes.activeIndicators }}
        indicatorContainerProps={{ className: classes.indicatorsContainer }}
        navButtonsProps={{ className: classes.navButtons }}
        navButtonsWrapperProps={{ className: classes.buttonWrapper }}
        fullHeightHover={false}
      >
        {images.length > 0 ? (
          images.map((file: CarouselImage) => (
            <ImageListItem key={file.imageSrc} style={{ height: 200 }}>
              <img
                style={{
                  height: '100%',
                  maxHeight: '100%',
                  borderRadius: 4,
                }}
                src={file.imageSrc}
                alt={file.altText}
              />
              {isNotEmptyField(file.tooltipTitle) && (
                <ImageListItemBar
                  position="bottom"
                  subtitle={file.tooltipTitle}
                />
              )}
              <ImageListItemBar
                sx={{ background: 'none' }}
                position="top"
                actionIcon={(
                  <IconButton
                    sx={{ color: 'rgba(255, 255, 255, 0.54)' }}
                    aria-label={`info about ${file.altText}`}
                    size="small"
                    onClick={() => setCurrentImage(file)}
                  >
                    <ZoomOutMapOutlined fontSize="small" />
                  </IconButton>
                )}
              />
            </ImageListItem>
          ))
        ) : (
          <Paper elevation={1} sx={{ width: '100%', height: '100%' }}>
            <Skeleton
              variant="rectangular"
              width="100%"
              height="100%"
              animation={false}
            />
          </Paper>
        )}
      </Carousel>
      <Modal open={currentImage !== null} onClose={() => setCurrentImage(null)}>
        <Box sx={modalStyle}>
          <img
            src={currentImage?.imageSrc}
            alt={currentImage?.altText}
            style={{ maxWidth: '80vw', maxHeight: '80vh' }}
          />
        </Box>
      </Modal>
    </>
  );
};

export default ImageCarousel;
