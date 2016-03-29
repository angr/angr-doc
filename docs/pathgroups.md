Bulk Execution and Exploration - Path Groups
============================================

Path groups are just a bunch of paths being executed at once. They are also the future.

```python
import angr
p = angr.Project(whatever)
pg = p.factory.path_group()
while len(pg.active) == 1:
    pg.step()

print 'Symbolic execution branched at block %#x' % pg.active[0].addr_trace[-1]
print 'Guard condition:', pg.active[0].actions[-1].condition
for i, path in enumerate(pg.active):
    print '- Child %d at %#x' % (i, path.addr)
```

HUGE TODO!
