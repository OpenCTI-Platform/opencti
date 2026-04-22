import React, { FunctionComponent, useCallback, useEffect, useRef, useState } from 'react';
import Carousel from 'react-material-ui-carousel';
import { Box, Modal, SxProps } from '@mui/material';
import { KeyboardArrowLeft, KeyboardArrowRight } from '@mui/icons-material';
import IconButton from '../common/button/IconButton';

export type MarkdownPreviewImage = {
  src: string;
  alt: string;
};

interface MarkdownImagePreviewModalProps {
  open: boolean;
  images: MarkdownPreviewImage[];
  initialIndex: number;
  onClose: () => void;
}

const imageModalStyle: SxProps = {
  position: 'fixed',
  top: '50%',
  left: '50%',
  transform: 'translate(-50%, -50%)',
  width: '90vw',
  maxWidth: 1200,
  height: '85vh',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  outline: 'none',
};

const navWrapperStyle: React.CSSProperties = {
  top: '50%',
  bottom: 'auto',
  height: 'auto',
  transform: 'translateY(-50%)',
  background: 'transparent',
};

const captionStyle: SxProps = {
  maxWidth: '85%',
  padding: '6px 10px',
  color: '#fff',
  fontSize: '0.85rem',
  lineHeight: 1.4,
  textAlign: 'center',
  borderRadius: 1,
  backgroundColor: 'rgba(0, 0, 0, 0.5)',
  marginTop: 2,
};

const MarkdownImagePreviewModal: FunctionComponent<MarkdownImagePreviewModalProps> = ({
  open,
  images,
  initialIndex,
  onClose,
}) => {
  const prevActionRef = useRef<(() => void) | null>(null);
  const nextActionRef = useRef<(() => void) | null>(null);
  const [activeIndex, setActiveIndex] = useState(initialIndex);

  useEffect(() => {
    if (open) {
      setActiveIndex(initialIndex);
    }
  }, [initialIndex, open]);

  const handleKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      event.stopPropagation();
      prevActionRef.current?.();
      return;
    }
    if (event.key === 'ArrowRight') {
      event.preventDefault();
      event.stopPropagation();
      nextActionRef.current?.();
    }
  }, []);

  return (
    <Modal
      open={open}
      onClose={onClose}
      onKeyDown={handleKeyDown}
      slotProps={{
        backdrop: {
          sx: {
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
          },
        },
      }}
    >
      <Box
        sx={imageModalStyle}
        onClick={onClose}
      >
        {images.length > 1 ? (
          <Carousel
            autoPlay={false}
            animation="slide"
            indicators={images.length > 1}
            index={activeIndex}
            onChange={(now) => {
              if (typeof now === 'number') {
                setActiveIndex(now);
              }
            }}
            navButtonsAlwaysVisible={images.length > 1}
            navButtonsWrapperProps={{
              style: navWrapperStyle,
            }}
            NavButton={({ onClick, next }) => {
              const run = () => onClick?.();
              if (next) {
                nextActionRef.current = run;
              } else {
                prevActionRef.current = run;
              }

              return (
                <IconButton
                  aria-label={next ? 'Next image' : 'Previous image'}
                  onClick={(event) => {
                    event.stopPropagation();
                    run();
                  }}
                  sx={{
                    color: '#fff',
                    backgroundColor: 'rgba(0, 0, 0, 0.45)',
                    '&:hover': {
                      backgroundColor: 'rgba(0, 0, 0, 0.65)',
                    },
                  }}
                >
                  {next ? <KeyboardArrowRight /> : <KeyboardArrowLeft />}
                </IconButton>
              );
            }}
            sx={{ width: '100%', height: '100%' }}
          >
            {images.map((image) => (
              <Box
                key={`${image.src}-${image.alt}`}
                sx={{
                  width: '100%',
                  height: '85vh',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <img
                  src={image.src}
                  alt={image.alt}
                  style={{ maxWidth: '90vw', maxHeight: image.alt ? '74vh' : '80vh' }}
                  onClick={(event) => event.stopPropagation()}
                />
                {image.alt && (
                  <Box sx={captionStyle} onClick={(event) => event.stopPropagation()}>
                    {image.alt}
                  </Box>
                )}
              </Box>
            ))}
          </Carousel>
        ) : (
          images[0] && (
            <Box
              sx={{
                width: '100%',
                height: '85vh',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <img
                src={images[0].src}
                alt={images[0].alt}
                style={{ maxWidth: '90vw', maxHeight: images[0].alt ? '74vh' : '80vh' }}
                onClick={(event) => event.stopPropagation()}
              />
              {images[0].alt && (
                <Box sx={captionStyle} onClick={(event) => event.stopPropagation()}>
                  {images[0].alt}
                </Box>
              )}
            </Box>
          )
        )}
      </Box>
    </Modal>
  );
};

export default MarkdownImagePreviewModal;
