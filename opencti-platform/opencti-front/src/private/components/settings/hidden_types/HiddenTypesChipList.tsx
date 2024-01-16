import React from 'react';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import useEntitySettings from '../../../../utils/hooks/useEntitySettings';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

const useStyles = makeStyles<Theme>((theme) => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
  grey_chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.grey?.[700],
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

const HiddenTypesChipList = ({
  hiddenTypes = [],
}: {
  hiddenTypes: readonly string[]
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const hiddenTypesGlobal = useEntitySettings()
    .filter((entitySetting) => entitySetting.platform_hidden_type === true)
    .map((hiddenType) => hiddenType.target_type);
  const diff = hiddenTypesGlobal.filter((hiddenTypeGlobal) => !hiddenTypes?.includes(hiddenTypeGlobal));

  return (<>
    <Typography variant="h3" gutterBottom={true}>
      {t_i18n('Hidden entity types')}
    </Typography>
    <FieldOrEmpty source={hiddenTypesGlobal.concat(hiddenTypes)}>
      {diff.map((hiddenTypeGlobal) => (<Chip
        key={hiddenTypeGlobal}
        classes={{ root: classes.grey_chip }}
        label={t_i18n(`entity_${hiddenTypeGlobal}`)}
                                       />))}
      {hiddenTypes.map((hiddenType) => (<Chip
        key={hiddenType}
        classes={{ root: classes.chip }}
        label={t_i18n(`entity_${hiddenType}`)}
                                        />))}
    </FieldOrEmpty>
  </>
  );
};

export default HiddenTypesChipList;
