# dev2/ — placeholder slot

Reserved for the Dev2 passive discovery module (see the `dev2` branch). Drop `dev2.py`, `scope.py`, `parsers.py`, `Dockerfile`, and `keys.example.env` here when adopting this tree.

- Attach contract: same four flags plus rate flags; exposes `run(targets, mode, scope_file, out, **opts) -> int`; writes `dev2.json` (`{host, ips}`, `ips` non-empty).
- Owner: Dev2 branch. This file is a pointer placeholder on the `dev3` integration branch — replace it with the module README when you adopt the layout.
