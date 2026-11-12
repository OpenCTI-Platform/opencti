import React from 'react';
import * as R from 'ramda';
import { styled } from '@mui/material/styles';
import { isEmptyField } from '../../utils/utils';
import { capitalizeFirstLetter } from '../../utils/String';

export const SYSTEM_BANNER_HEIGHT = 20;
const BANNER_Z_INDEX = 2000;

const Banner = styled('div')({
  textAlign: 'center',
  height: `${SYSTEM_BANNER_HEIGHT}px`,
  width: '100%',
  position: 'fixed',
  zIndex: BANNER_Z_INDEX,
});

const ClassificationText = styled('span')({
  height: `${SYSTEM_BANNER_HEIGHT - 4}px`,
  fontFamily: 'Arial,Helvetica,Geneva,Swiss,sans-serif',
  fontWeight: 'bold',
  padding: '2px 0',
  position: 'relative',
});

const bannerBackgrounds = {
  bannerGreen: '#00840C',
  bannerRed: '#ef0000',
  bannerYellow: '#ffff00',
};

const classificationTextColors = {
  classificationTextGreen: '#ffff00',
  classificationTextRed: '#ffffff',
  classificationTextYellow: '#000000',
};

const bannerColorClassName = (color, prefix = 'banner') => {
  if (!R.is(String, color)) {
    return '';
  }
  let colorName = color.toLowerCase();
  colorName = capitalizeFirstLetter(colorName);
  return `${prefix}${colorName}`;
};

const SystemBanners = ({ settings }) => {
  const bannerLevel = settings.platform_banner_level;
  const bannerText = settings.platform_banner_text;
  const bannerColor = bannerColorClassName(bannerLevel);
  const bannerTextColor = bannerColorClassName(
    bannerLevel,
    'classificationText',
  );
  const background = bannerBackgrounds[bannerColor];
  const color = classificationTextColors[bannerTextColor];
  if (isEmptyField(bannerLevel) || isEmptyField(bannerText)) {
    return <></>;
  }
  return (
    <>
      <Banner sx={{ top: 0, background }}>
        <ClassificationText sx={{ color }}>{bannerText}</ClassificationText>
      </Banner>
      <Banner sx={{ bottom: 0, background }}>
        <ClassificationText sx={{ color }}>{bannerText}</ClassificationText>
      </Banner>
    </>
  );
};

export default SystemBanners;
