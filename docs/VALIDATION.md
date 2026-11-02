# HDI 0.1.0 validation gate

This branch exists to trigger the repository CI matrix against the 0.1.0 reference implementation. Required checks are pytest and Ruff on Python 3.11, 3.12, and 3.13. A green CI run validates the test suite and lint configuration only; it is not an independent security audit or proof of production readiness.
