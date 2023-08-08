import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  indication: {
    fontSize: 12,
    color: theme.palette.primary.main,
  },
}));

interface Entity {
  readonly id: string;
  readonly name: string;
  readonly default_hidden_types: ReadonlyArray<string> | null;
}

interface HiddenTypesIndicatorProps {
  targetTypes: string[]
  platformHiddenTargetType: string
  nodes: Array<Entity | undefined>
  label: string
}

const HiddenTypesIndicator: FunctionComponent<HiddenTypesIndicatorProps> = ({
  targetTypes,
  platformHiddenTargetType,
  nodes,
  label,
}) => {
  const classes = useStyles();

  let hiddenTypesGrouped = {} as Record<string, string[]>;
  targetTypes.forEach((targetType) => {
    hiddenTypesGrouped = {
      ...hiddenTypesGrouped,
      [targetType]: [],
    };
  });

  nodes.forEach((node) => {
    if (node?.default_hidden_types) {
      node.default_hidden_types.forEach((hiddenType) => {
        if (hiddenType) {
          hiddenTypesGrouped[hiddenType].push(node.name);
        }
      });
    }
  });

  return (
    <span>
      {hiddenTypesGrouped[platformHiddenTargetType].length > 0
        && (<span className={classes.indication}>
              &emsp;
          {`(${label} : ${hiddenTypesGrouped[platformHiddenTargetType]})`}
            </span>)
      }
    </span>
  );
};

export default HiddenTypesIndicator;
