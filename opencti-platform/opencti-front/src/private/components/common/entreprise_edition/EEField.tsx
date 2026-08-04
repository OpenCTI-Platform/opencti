import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../../components/i18n';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  labelRoot: {
    '& .MuiFormLabel-root': {
      zIndex: 1,
    },
  },
});

interface EEFieldProps {
  children: React.ReactElement;
  featureLabel: string;
}

const EEField: FunctionComponent<EEFieldProps> = ({ children, featureLabel }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const component = React.cloneElement(children, {
    // @ts-expect-error child component prop types are unknown, so injected label prop can't be type-checked
    label: (
      <>
        {
          // @ts-expect-error children.props is untyped since children is a generic ReactElement
          t_i18n(children.props.label)
        }
        <EEChip feature={featureLabel} />
      </>
    ),
  });
  return <div className={classes.labelRoot}>{component}</div>;
};

export default EEField;
