import React from 'react';
import * as PropTypes from 'prop-types';
import { ArrowUpward, ArrowDownward, ArrowForward } from '@mui/icons-material';

import inject18n from './i18n';
import { alpha } from '@mui/material';
import { styled, useTheme } from '@mui/material/styles';

const Diff = styled('div')({
  float: 'left',
  margin: '23px 0 0 10px',
  padding: '2px 5px 2px 5px',
  fontSize: 12,
});

const DiffDescription = styled('div')(({ theme }) => ({
  margin: '2px 0 0 10px',
  float: 'left',
  fontSize: 9,
  color: theme.palette.text.primary,
}));

const DiffNumber = styled('div')({
  float: 'left',
});

const diffIconSx = {
  float: 'left',
  margin: '1px 5px 0 0',
  fontSize: 13,
};

const ItemNumberDifference = (props) => {
  const { t, difference, description } = props;
  const theme = useTheme();

  const inlineStyles = {
    green: {
      backgroundColor: alpha(theme.palette.severity.low, 0.08),
      color: theme.palette.severity.low,
    },
    red: {
      backgroundColor: alpha(theme.palette.severity.critical, 0.08),
      color: theme.palette.severity.critical,
    },
    blueGrey: {
      backgroundColor: alpha(theme.palette.severity.default, 0.08),
      color: theme.palette.severity.default,
    },
  };

  if (difference < 0) {
    return (
      <Diff style={inlineStyles.red}>
        <ArrowDownward color="inherit" sx={diffIconSx} />
        <DiffNumber>{difference}</DiffNumber>
        {description ? (
          <DiffDescription>({t(description)})</DiffDescription>
        ) : (
          ''
        )}
      </Diff>
    );
  }
  if (difference === 0) {
    return (
      <Diff style={inlineStyles.blueGrey}>
        <ArrowForward color="inherit" sx={diffIconSx} />
        <DiffNumber>{difference}</DiffNumber>
        {description ? (
          <DiffDescription>({t(description)})</DiffDescription>
        ) : (
          ''
        )}
      </Diff>
    );
  }
  return (
    <Diff style={inlineStyles.green}>
      <ArrowUpward color="inherit" sx={diffIconSx} />
      <DiffNumber>{difference}</DiffNumber>
      {description ? (
        <DiffDescription>({t(description)})</DiffDescription>
      ) : (
        ''
      )}
    </Diff>
  );
};

ItemNumberDifference.propTypes = {
  t: PropTypes.func,
  difference: PropTypes.number,
  description: PropTypes.string.isRequired,
};

export default inject18n(ItemNumberDifference);
