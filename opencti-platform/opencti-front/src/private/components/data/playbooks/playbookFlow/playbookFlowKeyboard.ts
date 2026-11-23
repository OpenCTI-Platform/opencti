import type { ReactFlowProps } from 'reactflow';

// React Flow makes every node wrapper a focusable role="button" and every edge a Tab stop named by
// its ids. A playbook card already holds its own buttons (the title that opens the configuration and
// the step menu), so the wrapper would be a button around buttons (nested-interactive, WCAG 4.1.2)
// with a spoken hint about moving nodes that cannot move. The keyboard path is the card's own buttons
// and "Insert a component on this link"; nodes and edges stay out of the Tab order, and the library's
// node and edge descriptions ("Press enter or space to select a node...") are dropped with
// disableKeyboardA11y. The links are named after their steps by usePlaybookEdgeNames.
const playbookFlowKeyboardProps = {
  nodesFocusable: false,
  edgesFocusable: false,
  disableKeyboardA11y: true,
} as const satisfies Partial<ReactFlowProps>;

export default playbookFlowKeyboardProps;
