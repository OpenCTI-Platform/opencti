import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';
import { FiligranLoader } from 'filigran-icon';
import { useTheme } from '@mui/material/styles';
import { interval } from 'rxjs';
import Typography from '@mui/material/Typography';
import { UserContext } from '../utils/hooks/useAuth';
import type { Theme } from './Theme';
import { TEN_SECONDS } from '../utils/Time';

const interval$ = interval(TEN_SECONDS);

const containerSx = {
  width: '100%',
  minWidth: '100%',
  height: '100%',
  minHeight: 'calc(100vh - 180px)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
} as const;

const containerInElementSx = {
  width: '100%',
  height: '100%',
  display: 'table',
} as const;

const loaderSx = {
  width: '5rem',
  zIndex: 20,
} as const;

const loaderInElementSx = {
  width: '5rem',
  margin: 0,
  padding: 0,
  display: 'table-cell',
  verticalAlign: 'middle',
  textAlign: 'center',
} as const;

const loaderCircleSx = {
  width: '5rem',
  display: 'inline-block',
} as const;

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
  const theme = useTheme<Theme>();
  const { settings } = useContext(UserContext);
  const [currentText, setCurrentText] = useState(0);
  // if you have EE and whitemark set, you can remove the loader
  const hasFiligranLoader = theme && !(settings?.platform_enterprise_edition?.license_validated && settings?.platform_whitemark);
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
      <div
        role="progressbar"
        aria-label="Loading..."
        style={{ display: 'inline-flex', width: '4rem', height: 35, alignItems: 'center', justifyContent: 'center' }}
      >
        {hasFiligranLoader ? (
          <FiligranLoader height={24} color={theme?.palette?.common?.grey} />
        ) : (
          <CircularProgress
            aria-hidden
            size={24}
            thickness={1}
            sx={loaderCircleSx}
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
    <Box
      sx={variant === 'inElement' ? containerInElementSx : containerSx}
      style={
        variant === 'inElement'
          ? {
              paddingRight: withRightPadding ? 200 : 0,
              marginTop: withTopMargin ? 200 : 0,
            }
          : {}
      }
    >
      <Box
        role="progressbar"
        aria-label="Loading..."
        sx={
          variant === 'inElement' ? loaderInElementSx : loaderSx
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
            aria-hidden
            size={variant === 'inElement' ? 40 : 80}
            thickness={1}
            sx={loaderCircleSx}
          />
        )}
        {rotatingTexts && rotatingTexts.length > 0 && (
          <Typography variant="body2">
            {rotatingTexts[currentText]}...
          </Typography>
        )}
      </Box>
    </Box>
  );
};

export default Loader;
