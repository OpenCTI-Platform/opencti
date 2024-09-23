import React from 'react';
import Slide from '@mui/material/Slide';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import RulesList, { rulesListQuery } from './RulesList';
import SearchInput from '../../../components/SearchInput';
import { UserContext } from '../../../utils/hooks/useAuth';
import { dayAgo, yearsAgo } from '../../../utils/Time';
import { RULE_ENGINE } from '../../../utils/platformModulesHelper';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import CustomizationMenu from './CustomizationMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'rules';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  parameters: {
    float: 'left',
    marginTop: -10,
  },
}));

const Rules = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {},
  );
  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Rules engine'), current: true }]} />
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => {
          if (!platformModuleHelpers.isRuleEngineEnable()) {
            return (
              <Alert severity="info">
                {t_i18n(platformModuleHelpers.generateDisableMessage(RULE_ENGINE))}
              </Alert>
            );
          }
          return (
            <>
              <div className={classes.parameters}>
                <div style={{ float: 'left', marginRight: 20 }}>
                  <SearchInput
                    variant="small"
                    onSubmit={helpers.handleSearch}
                    keyword={viewStorage.searchTerm ?? ''}
                  />
                </div>
              </div>
              <div className="clearfix" />
              <QueryRenderer
                query={rulesListQuery}
                variables={{ startDate: yearsAgo(1), endDate: dayAgo() }}
                render={({ props }) => {
                  if (props) {
                    return (
                      <RulesList
                        data={props}
                        keyword={viewStorage.searchTerm ?? ''}
                      />
                    );
                  }
                  return <div />;
                }}
              />
            </>
          );
        }}
      </UserContext.Consumer>
    </div>
  );
};

export default Rules;
