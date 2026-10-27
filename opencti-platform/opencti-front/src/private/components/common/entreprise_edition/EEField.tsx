import React, { FunctionComponent } from 'react';
import { styled } from '@mui/material/styles';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../../components/i18n';

const LabelRoot = styled('div')({
  '& .MuiFormLabel-root': {
    zIndex: 1,
  },
});

interface EEFieldProps {
  children: React.ReactElement;
  featureLabel: string;
}

const EEField: FunctionComponent<EEFieldProps> = ({
  children,
  featureLabel,
}) => {
  const { t_i18n } = useFormatter();
  const component = React.cloneElement(children, {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    label: <>{t_i18n(children.props.label)}<EEChip feature={featureLabel} /></>,
  });
  return (
    <LabelRoot>
      {component}
    </LabelRoot>
  );
};

export default EEField;
