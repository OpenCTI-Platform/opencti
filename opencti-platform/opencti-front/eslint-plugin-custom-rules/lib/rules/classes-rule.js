module.exports = {
  meta: {
    type: "problem",
    fixable: "code",
    docs: {
      description: "MakeStyles should define only the classes used in the component"
    },
  },
  create: (context) => {
    const sourceCode = context.sourceCode;
    return {
      VariableDeclarator(node) {
        if (node.init && ((node.init.left && node.init.left.name === "makeStyles")
          || (node.init.callee && node.init.callee.name === "makeStyles"))) {
          if (node.id.name !== "useStyles") {
            context.report({
              node: node,
              message: "MakeStyle must be declared as useStyles",
              fix(fixer) {
                return fixer.replaceText(node.id, "useStyles")
              },
            });
          }
        }
        if (node.init && node.init.callee && node.init.callee.name === "useStyles") {
          if (node.id.name !== "classes") {
            context.report({
              node: node,
              message: "useStyles must be declared as classes",
              fix(fixer) {
                return fixer.replaceText(node.id, "classes")
              },
            });
          }
        }
      },
      ArrowFunctionExpression(node) {
        if (node.parent.callee && node.parent.callee.name === "makeStyles") {
          if (!node.body.properties) {
            if (!node.body.body) {
              context.report({
                node: node,
                message: "MakeStyles is used with no class declared",
                data: {
                  identifier: node.name
                }
              });
            }
          } else {
            node.body.properties.forEach((v) => {
              if (!sourceCode.text.includes("classes." + v.key.name)) {
                context.report({
                  node: node,
                  message: "Styled class is not used in component",
                  data: {
                    identifier: v
                  },
                  fix(fixer) {
                    const startLine = v.loc.start.line
                    const endLine = v.loc.end.line
                    return fixer.removeRange([
                      sourceCode.getIndexFromLoc({ line: startLine, column: 0 }),
                      sourceCode.getIndexFromLoc({ line: endLine + 1, column: 0 })
                    ])
                  }
                });
              }
            })
          }
        }
      }
    };
  },
}