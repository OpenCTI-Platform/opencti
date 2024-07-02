import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import { itemColor } from 'src/utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

interface EntityRelationshipCardProps {
  entityName: string;
  entityType: string;
}

const EntityRelationshipCard : FunctionComponent<EntityRelationshipCardProps> = ({ entityName, entityType }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  return (
    <>
      <div style={{
        width: 180,
        height: 80,
        borderRadius: 10,
        top: 10,
        right: 10,
        border: `1px solid ${itemColor(entityType)}`,
      }}
      >
        <div style={{
          padding: '10px 0 10px 0',
          borderBottom: `1px solid ${itemColor(entityType)}`,
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
        }}
        >
          <div style={{
            display: 'flex',
            gap: '12px',
          }}
          >
            <div style={{
              position: 'absolute',
              top: 8,
              left: 5,
              fontSize: 8,
            }}
            >
              <ItemIcon
                type={entityType}
                color={itemColor(entityType)}
                size="small"
              />
            </div>
            <div style={{ width: '100%', textAlign: 'center', color: theme.palette.text?.primary, fontSize: 11 }}>
              {t_i18n(`entity_${entityType}`)}
            </div>
          </div>
        </div>
        <div style={{
          width: '100%',
          height: 40,
          maxHeight: 40,
          lineHeight: '40px',
          color: theme.palette.text?.primary,
          textAlign: 'center',
          fontSize: 12,
        }}
        >
          {t_i18n(entityName)}
        </div>
      </div>
    </>
  );
};

export default EntityRelationshipCard;
