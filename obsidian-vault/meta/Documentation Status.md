---
title: Documentation Status
type: meta
tags: [meta]
status: documented
created: 2026-06-26
---
# Documentation Status

Tracks which notes still need filling in. Edit a note's `status` (stub → in-progress → documented) to update this table.

```dataview
TABLE type, status, file.folder AS folder
WHERE status != "documented"
SORT status ASC, file.name ASC
```

## Related
[[Tasks]] · [[Orphan Check]] · [[00 - Project Map (MOC)]]

---
#meta
