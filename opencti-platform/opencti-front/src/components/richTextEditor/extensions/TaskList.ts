import { TaskList as TaskListBase } from '@tiptap/extension-task-list';

export const TaskList = TaskListBase.extend({
  parseHTML() {
    return [
      // Default Tiptap
      {
        tag: `ul[data-type="${this.name}"]`,
        priority: 51,
      },
      // Legacy editor
      {
        tag: 'ul.todo-list',
        priority: 52,
      },
    ];
  },
});
