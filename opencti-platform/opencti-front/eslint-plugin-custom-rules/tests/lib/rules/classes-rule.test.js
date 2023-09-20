const rule = require("../../../lib/rules/classes-rule"),
  RuleTester = require("eslint").RuleTester;


const ruleTester = new RuleTester({
  parserOptions: {
    ecmaVersion: 2020,
    project: '../tsconfig.json',
  }
});
ruleTester.run("classes-rule", rule, {
  valid: [
    // give me some code that won't trigger a warning
    {
      code: `
        const useStyles = makeStyles((theme) => ({
          container: {
            padding: 0,
          },
          avatar: {
            width: 24,
            height: 24,
          },
        }));
        classes.avatar;
        classes.container;
      `,
    }, {
      code: `
      const useStyles = makeStyles((theme) => {
        const {
          bannerSettings: { bannerHeightNumber },
        } = useAuth();
        return ({
          drawerPaper: {
            minHeight: '100vh',
            width: '50%',
            position: 'fixed',
            overflow: 'auto',
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp, duration: theme.transitions.duration.enteringScreen,
            }),
            paddingTop: \`${0}px\`,
            paddingBottom: \`${0}px\`,
          },
          header: {
            backgroundColor: theme.palette.background.nav,
            padding: '10px 0',
            display: 'inline-flex',
            alignItems: 'center',
          },
          container: {
            padding: '10px 20px 20px 20px',
          },
          mainButton: {
            position: 'fixed',
            bottom: \`${0 + 30}px\`,
          },
          withPanel: {
            right: 230,
          },
          noPanel: {
            right: 30,
          },
        });
      });
      `
    }
  ],

  invalid: [
    {
      code: `
        const useStyles = makeStyles((theme) => ({
          drawerPaper: {
            minHeight: '100vh',
            width: '50%',
            position: 'fixed',
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.enteringScreen,
            }),
            padding: 0,
          },
          container: {
            padding: 0,
          },
          avatar: {
            width: 24,
            height: 24,
          },
        }));
        classes.avatar;
        classes.container;
      `,
      errors: 1,
      output: `
        const useStyles = makeStyles((theme) => ({
          container: {
            padding: 0,
          },
          avatar: {
            width: 24,
            height: 24,
          },
        }));
        classes.avatar;
        classes.container;
      `,
    },
  ],
});
console.log("All tests passed!");