import React, { FunctionComponent } from 'react';
import Carousel from 'react-material-ui-carousel';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { convertImagesToCarousel } from '../utils/edition';
import noImage from '../static/images/leaflet/no-image-placeholder.png';

const useStyles = makeStyles(() => ({
  carousel: {
    textAlign: 'center',
  },
}));

interface Image {
  id: string;
  description: string | null;
  name: string;
  inCarousel: boolean | null;
}

interface ImageCarouselProps {
  data: {
    images: readonly Image[] | null;
  }
}

interface CarouselImage {
  tooltipTitle:string
  imageSrc: string
  altText: string
  id: string
}

const ImageCarousel: FunctionComponent<ImageCarouselProps> = ({ data }) => {
  const classes = useStyles();
  const images = convertImagesToCarousel(data);

  return (
    <Carousel height='150px' className={classes.carousel} animation='fade'>
      {images.length > 0 ? (
        images.map((file: CarouselImage) => (
          <Tooltip title={file.tooltipTitle} key={file.id} placement='right'>
            <img
              style={{ height: '100%' }}
              src={file.imageSrc}
              alt={file.altText}
            />
          </Tooltip>
        ))) : (
        <img
          style={{ height: '100%' }}
          src={noImage}
          alt="No Image"
        />
      )}
    </Carousel>
  );
};

export default ImageCarousel;
