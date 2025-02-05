import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import CircularProgress from '@mui/material/CircularProgress';
import makeStyles from '@mui/styles/makeStyles';
import { FiligranLoader } from 'filigran-icon';
import { useTheme } from '@mui/styles';
import { interval } from 'rxjs';
import Typography from '@mui/material/Typography';
import { UserContext } from '../utils/hooks/useAuth';
import type { Theme } from './Theme';
import { TEN_SECONDS } from '../utils/Time';

const interval$ = interval(TEN_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    minWidth: '100%',
    height: '100%',
    minHeight: 'calc(100vh - 180px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  containerInElement: {
    width: '100%',
    height: '100%',
    display: 'table',
  },
  loader: {
    width: '5rem',
    zIndex: 20,
  },
  loaderInElement: {
    width: '5rem',
    margin: 0,
    padding: 0,
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
  },
  loaderCircle: {
    width: '5rem',
    display: 'inline-block',
  },
}));

export enum LoaderVariant {
  container = 'container',
  inElement = 'inElement',
  inline = 'inline',
}

interface LoaderProps {
  variant?: LoaderVariant;
  withRightPadding?: boolean;
  withTopMargin?: boolean;
  rotatingTexts?: Array<string>;
}

const Loader: FunctionComponent<LoaderProps> = ({
  variant = LoaderVariant.container,
  withRightPadding = false,
  withTopMargin = false,
  rotatingTexts,
}) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { settings } = useContext(UserContext);
  const [currentText, setCurrentText] = useState(0);
  // if you have EE and whitemark set, you can remove the loader
  const hasFiligranLoader = theme && !(settings?.platform_enterprise_edition.license_validated && settings?.platform_whitemark);
  if (rotatingTexts && rotatingTexts.length > 0) {
    useEffect(() => {
      const subscription = interval$.subscribe(() => {
        if (currentText === rotatingTexts.length - 1) {
          setCurrentText(0);
        } else {
          setCurrentText(currentText + 1);
        }
      });
      return () => {
        subscription.unsubscribe();
      };
    });
  }
  if (variant === 'inline') {
    return (
      <div style={{ display: 'inline-flex', width: '4rem', height: 35, alignItems: 'center', justifyContent: 'center' }}>
        {hasFiligranLoader ? (
          <FiligranLoader height={24} color={theme?.palette?.common?.grey} />
        ) : (
          <CircularProgress
            size={24}
            thickness={1}
            className={classes.loaderCircle}
          />
        )}
        {rotatingTexts && rotatingTexts.length > 0 && (
          <Typography variant="body2">
            {rotatingTexts[currentText]}...
          </Typography>
        )}
      </div>
    );
  }
  return (
    <div
      className={variant === 'inElement' ? classes.containerInElement : classes.container}
      style={
        variant === 'inElement'
          ? {
            paddingRight: withRightPadding ? 200 : 0,
            marginTop: withTopMargin ? 200 : 0,
          }
          : {}
      }
    >
      <div
        className={
          variant === 'inElement' ? classes.loaderInElement : classes.loader
        }
        style={
          variant !== 'inElement'
            ? { paddingRight: withRightPadding ? 100 : 0 }
            : {}
        }
      >
        {hasFiligranLoader ? (
          <FiligranLoader height={variant === 'inElement' ? 40 : 80} color={theme?.palette?.common?.grey} />
        ) : (
          <CircularProgress
            size={variant === 'inElement' ? 40 : 80}
            thickness={1}
            className={classes.loaderCircle}
          />
        )}
        {rotatingTexts && rotatingTexts.length > 0 && (
          <Typography variant="body2">
            {rotatingTexts[currentText]}...
          </Typography>
        )}
      </div>
    </div>
  );
};

export default Loader;
