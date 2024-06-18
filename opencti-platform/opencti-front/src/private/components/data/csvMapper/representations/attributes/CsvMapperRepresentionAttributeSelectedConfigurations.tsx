import React, { FunctionComponent } from 'react';
import { SubdirectoryArrowRight } from 'mdi-material-ui';
import { CsvMapperRepresentationAttributeFormData } from '@components/data/csvMapper/representations/attributes/Attribute';
import { useFormatter } from '../../../../../../components/i18n';

interface CsvMapperRepresentationAttributeSelectedConfigurationsProps {
  configuration?: CsvMapperRepresentationAttributeFormData
}

const flexStyle = { display: 'flex', alignItems: 'end', gap: '4px' };
const containerStyle = { gridColumnStart: 2, gridColumnEnd: 4 };

const CsvMapperRepresentationAttributeSelectedConfigurations:
FunctionComponent<CsvMapperRepresentationAttributeSelectedConfigurationsProps> = ({ configuration }) => {
  const { t_i18n } = useFormatter();
  if (!configuration?.pattern_date && !configuration?.separator) {
    return null;
  }

  return (
    <div style={containerStyle}>
      {
        configuration.pattern_date
        && <div style={flexStyle}>
          <SubdirectoryArrowRight />{t_i18n('Date pattern')}:
          <span>{configuration.pattern_date}</span>
        </div>
      }
      {
        configuration.separator
        && <div style={flexStyle}>
          <SubdirectoryArrowRight /> {t_i18n('List separator')}:
          <span>{configuration.separator}</span>
        </div>
      }
    </div>
  );
};

export default CsvMapperRepresentationAttributeSelectedConfigurations;
