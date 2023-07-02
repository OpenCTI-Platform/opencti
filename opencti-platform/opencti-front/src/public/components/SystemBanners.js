import React from 'react';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import {isEmptyField} from "../../utils/utils";

export const SYSTEM_BANNER_HEIGHT = 20;
const BANNER_Z_INDEX = 2000;

const useStyles = makeStyles(() => ({
    banner: {
        textAlign: 'center',
        height: `${SYSTEM_BANNER_HEIGHT}px`,
        width: '100%',
        position: 'fixed',
        zIndex: BANNER_Z_INDEX,
    },
    bannerTop: {
        top: 0,
    },
    bannerBottom: {
        bottom: 0,
    },
    bannerGreen: {
        background: '#00840C',
    },
    bannerRed: {
        background: '#ef0000',
    },
    bannerYellow: {
        background: '#ffff00',
    },
    classificationText: {
        height: `${SYSTEM_BANNER_HEIGHT - 4}px`,
        fontFamily: 'Arial,Helvetica,Geneva,Swiss,sans-serif',
        fontWeight: 'bold',
        padding: '2px 0',
        position: 'relative',
    },
    classificationTextGreen: {
        color: '#ffff00',
    },
    classificationTextRed: {
        color: '#ffffff',
    },
    classificationTextYellow: {
        color: '#000000',
    },
}));

const bannerColorClassName = (color, prefix = 'banner') => {
    if (!R.is(String, color)) {
        return '';
    }
    let colorName = color.toLowerCase();
    colorName = colorName.substring(0, 1).toUpperCase() + colorName.substring(1);
    return `${prefix}${colorName}`;
}

const SystemBanners = ({ settings }) => {
    const classes = useStyles();
    const bannerLevel = settings.platform_banner_level;
    const bannerText = settings.platform_banner_text;
    const bannerColor = bannerColorClassName(bannerLevel);
    const bannerTextColor = bannerColorClassName(bannerLevel, 'classificationText');
    const topBannerClasses = [classes.banner, classes.bannerTop, classes[bannerColor]].join(' ');
    const bottomBannerClasses = [classes.banner, classes.bannerBottom, classes[bannerColor]].join(' ');
    const bannerTextClasses = [classes.classificationText, classes[bannerTextColor]].join(' ');
    if (isEmptyField(bannerLevel) || isEmptyField(bannerText)) {
        return <></>
    }
    return <div>
        <div className={topBannerClasses}>
              <span className={bannerTextClasses}>{bannerText}</span>
        </div>
        <div className={bottomBannerClasses}>
              <span className={bannerTextClasses}>{bannerText}</span>
        </div>
    </div>;
}

export default SystemBanners;
