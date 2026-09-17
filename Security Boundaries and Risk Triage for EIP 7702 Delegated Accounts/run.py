"""Source-checkout entry point; installed users can run guard7702."""
import sys
import unittest
from pathlib import Path

if __name__ == '__main__':
    if sys.argv[1:] == ['test']:
        suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / 'tests'))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    from guard7702.cli import main
    raise SystemExit(main())
