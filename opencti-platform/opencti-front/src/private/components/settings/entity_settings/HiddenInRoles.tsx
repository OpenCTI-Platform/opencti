import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { HiddenInRolesQuery } from './__generated__/HiddenInRolesQuery.graphql';

export const hiddenInRolesQuery = graphql`
    query HiddenInRolesQuery($search: String) {
        roles(search: $search) {
            edges {
                node {
                    id
                    name
                    default_hidden_types
                }
            }
        }
    }
`;

const useStyles = makeStyles<Theme>((theme) => ({
  roleIndication: {
    fontSize: 12,
    color: theme.palette.primary.main,
  },
}));

interface HiddenInRolesContentProps {
  queryRef: PreloadedQuery<HiddenInRolesQuery>,
  targetTypes: string[],
  platformHiddenTargetType: string,
}

const HiddenInRoles: FunctionComponent<HiddenInRolesContentProps> = ({ queryRef, targetTypes, platformHiddenTargetType }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  let hiddenTypesWithRoles = {} as Record<string, string[]>;
  const data = usePreloadedQuery<HiddenInRolesQuery>(hiddenInRolesQuery, queryRef);
  const rolesData = data.roles?.edges;
  for (const entity_type of targetTypes) {
    hiddenTypesWithRoles = {
      ...hiddenTypesWithRoles,
      [entity_type]: [],
    };
  }
  if (rolesData) {
    for (const r of rolesData) {
      if (r && r.node.default_hidden_types) {
        for (const hidden_type of r.node.default_hidden_types) {
          if (hidden_type) {
            hiddenTypesWithRoles[hidden_type].push(r.node.name);
          }
        }
      }
    }
  }

  return (
    <span>
      {hiddenTypesWithRoles[platformHiddenTargetType].length > 0
        && (<span className={classes.roleIndication}>
              &emsp;
          {`(${t('Hidden in roles')} : ${hiddenTypesWithRoles[platformHiddenTargetType]})`}
            </span>)
      }
    </span>
  );
};

export default HiddenInRoles;
