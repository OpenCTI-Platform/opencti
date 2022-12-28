import React, { FunctionComponent } from 'react';
import SentimentVeryDissatisfiedIcon from '@mui/icons-material/SentimentVeryDissatisfied';
import SentimentDissatisfiedIcon from '@mui/icons-material/SentimentDissatisfied';
import SentimentSatisfiedIcon from '@mui/icons-material/SentimentSatisfied';
import SentimentSatisfiedAltIcon from '@mui/icons-material/SentimentSatisfiedAltOutlined';
import SentimentVerySatisfiedIcon from '@mui/icons-material/SentimentVerySatisfied';
import Rating, { IconContainerProps } from '@mui/material/Rating';
import { styled } from '@mui/material/styles';

type CustomIcon = {
  [index: string]: {
    icon: React.ReactElement;
    label: string;
  };
};
export const customIcons = (fontSize: number): CustomIcon => ({
  1: {
    icon: <SentimentVeryDissatisfiedIcon color="error" sx={{ fontSize }} />,
    label: 'Very Dissatisfied',
  },
  2: {
    icon: <SentimentDissatisfiedIcon color="error" sx={{ fontSize }} />,
    label: 'Dissatisfied',
  },
  3: {
    icon: <SentimentSatisfiedIcon color="warning" sx={{ fontSize }} />,
    label: 'Neutral',
  },
  4: {
    icon: <SentimentSatisfiedAltIcon color="success" sx={{ fontSize }} />,
    label: 'Satisfied',
  },
  5: {
    icon: <SentimentVerySatisfiedIcon color="success" sx={{ fontSize }} />,
    label: 'Very Satisfied',
  },
});

export function IconContainer(props: IconContainerProps) {
  const { value, ...other } = props;
  return <span {...other}>{customIcons(30)[value].icon}</span>;
}

export function LargeIconContainer(props: IconContainerProps) {
  const { value, ...other } = props;
  return <span {...other}>{customIcons(64)[value].icon}</span>;
}

const StyledRating = styled(Rating)(({ theme }) => ({
  '& .MuiRating-iconEmpty .MuiSvgIcon-root': {
    color: theme.palette.action.disabled,
  },
}));

interface RatingProps {
  rating: number
  readOnly?: boolean
  style?: Record<string, unknown>
  size: 'small' | 'large'
  handleOnChange?: (value: number | null) => void
}

const RatingField: FunctionComponent<RatingProps> = ({ style, rating, handleOnChange, readOnly, size }) => {
  return <div style={style}>
    <StyledRating
      name='highlight-selected-only'
      value={rating}
      IconContainerComponent={size === 'small' ? IconContainer : LargeIconContainer}
      onChange={(_, value) => handleOnChange && handleOnChange(value)}
      highlightSelectedOnly
      readOnly={readOnly === true}
    />
  </div>;
};

export default RatingField;
