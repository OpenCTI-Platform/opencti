import React, { FunctionComponent } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '../../../../components/Theme';
import { HiddenInRolesQuery } from './__generated__/HiddenInRolesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

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

interface HiddenInRolesProps {
  targetTypes: string[],
  platformHiddenTargetType: string,
}

const HiddenInRoles: FunctionComponent<HiddenInRolesProps> = ({ targetTypes, platformHiddenTargetType }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const hiddenTypesWithRoles = () => {
    let result = {} as Record<string, string[]>;
    const data = useLazyLoadQuery<HiddenInRolesQuery>(hiddenInRolesQuery, {});
    const rolesData = data.roles?.edges;
    for (const entity_type of targetTypes) {
      result = {
        ...result,
        [entity_type]: [],
      };
    }
    if (rolesData) {
      for (const r of rolesData) {
        if (r && r.node.default_hidden_types) {
          for (const hidden_type of r.node.default_hidden_types) {
            if (hidden_type) {
              result[hidden_type].push(r.node.name);
            }
          }
        }
      }
    }
    return result;
  };

  const rolesHiddenTypes = hiddenTypesWithRoles();
  return (
    <span>
      {rolesHiddenTypes[platformHiddenTargetType].length > 0
        && (<span className={classes.roleIndication}>
              &emsp;
          {`(${t('Hidden in roles')} : ${rolesHiddenTypes[platformHiddenTargetType]})`}
            </span>)
      }
    </span>
  );
};

export default HiddenInRoles;
