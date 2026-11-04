import React, { FunctionComponent } from 'react';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../../components/i18n';

interface EEFieldProps {
  children: React.ReactElement;
  featureLabel: string;
}

const EEField: FunctionComponent<EEFieldProps> = ({
  children,
  featureLabel,
}) => {
  const { t_i18n } = useFormatter();
  return React.cloneElement(children, {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    label: <>{t_i18n(children.props.label)}<EEChip feature={featureLabel} /></>,
  });
};

export default EEField;
