# Delete and restore knowledge

Knowledge can be deleted from OpenCTI either in an overview of an object or using [background tasks](background-tasks.md).
When an object is deleted, all its relationships and references to other objects are also deleted. 

The deletion event is written to the [stream](../reference/streaming.md), to trigger automated [playbooks](./automation.md) or synchronize another platform.

Since OpenCTI 6.1, a record of the deleted objects is kept for a given period of a time, allowing to restore them on demand. This does not impact the stream events or other side effect of the deletion: the object is still _deleted_.


## Trash

A view called "Trash" displays all "delete" operations, entities and relationships alike.

![Trash](assets/trash.png)

A delete operation contains not only the entity or relationship that has been deleted, but also all the relationships and references from (to) this main object to (from) other elements in the platform.

You can sort, filter or search this table using the usual UI controls. You are limited to the type of object, their representation (most of the time, the _name_ of the object), the user who deleted the object, the date and time of deletion and the marking of the object.

Note that the delete operations (i.e. the entries in this table view) inherit the marking of the main entity that was deleted, and thus follow the same access restriction as the object that was deleted.

You can individually restore or permanently delete an object from the trash view using the burger menu at the end of the line.

![Trash actions](assets/trash-actions.png)

Alternatively, you can use the checkboxes at the start of the line to select a subset of deleted objects, and trigger a background task to restore or permanently delete them by batch.

## Restore

Restoring an element creates it again in the platform with the same information it had before its deletion.
It also restores all the relationships from or to this object, that have been also deleted during the deletion operation.
If the object had attached files (uploaded or exported), they are also restored.

![Trash restore confirm](assets/trash-restore-confirm.png)

## Permanent delete

From the Trash panel, it is also possible to delete permanently the object, its relationships, and attached files.

![Trash delete confirm](assets/trash-delete-confirm.png)

## Trash retention

Deleted objects are kept in trash during a fixed period of time (7 days by default), then they are permanently deleted by the [trash manager](../deployment/managers.md#trash-manager).

## Limitations

When it comes to restoring a deleted object from the trash, the current implementation shows several limitations. 
First and foremost, if an object in the trash has lost a relationship dependency (i.e. the other side of a relationship from or to this object is no longer in live database), you will not be able to restore the object.

![restore error: a dependency is in the trash](assets/trash-error-dependency-in-trash.png)

In such case, if the missing dependency is in the trash too, you can manually restore this dependency first and then retry.

If the missing dependency has been permanently deleted, the object cannot be recovered.

![restore error: a dependency is in the trash](assets/trash-error-dependency-missing.png)

In other words:
* **no partial restore**: the object and _all_ its relationships must be restored in one pass
* **no "cascading" restore**: restoring one object does not restore automatically all linked objects in the trash
