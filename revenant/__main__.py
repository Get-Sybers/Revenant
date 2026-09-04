"""Allow ``python -m revenant`` to invoke the CLI."""

import sys
from revenant.cli import main

sys.exit(main())
