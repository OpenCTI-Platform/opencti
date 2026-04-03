import { TaskItem as TaskItemBase } from '@tiptap/extension-task-item';

export const TaskItem = TaskItemBase.extend({
  parseHTML() {
    return [
      // Default Tiptap
      {
        tag: `li[data-type="${this.name}"]`,
        priority: 51,
      },
      // Legacy editor
      {
        tag: 'ul.todo-list > li',
        priority: 52,
      },
    ];
  },
});
