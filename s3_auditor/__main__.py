"""Lets you run the package directly:  python -m s3_auditor --demo"""

import sys

from .cli import main

sys.exit(main())
