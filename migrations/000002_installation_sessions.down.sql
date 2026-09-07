-- Invalidate bound credentials before rollback; old validators ignore sid.
DROP TABLE IF EXISTS authkit.sessions;
