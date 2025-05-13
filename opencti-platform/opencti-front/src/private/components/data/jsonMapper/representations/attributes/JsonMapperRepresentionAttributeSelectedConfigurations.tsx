import React, { FunctionComponent } from 'react';
import { SubdirectoryArrowRight } from 'mdi-material-ui';
import { JsonAttrPathConfiguration } from '@components/data/jsonMapper/representations/attributes/Attribute';
import { useFormatter } from '../../../../../../components/i18n';

interface JsonMapperRepresentationAttributeSelectedConfigurationsProps {
  configuration?: JsonAttrPathConfiguration | null
}

const flexStyle = { display: 'flex', alignItems: 'end', gap: '4px' };
const containerStyle = { gridColumnStart: 2, gridColumnEnd: 4 };

const JsonMapperRepresentationAttributeSelectedConfigurations:
FunctionComponent<JsonMapperRepresentationAttributeSelectedConfigurationsProps> = ({ configuration }) => {
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

export default JsonMapperRepresentationAttributeSelectedConfigurations;
