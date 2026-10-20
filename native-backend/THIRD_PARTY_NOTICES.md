# Third-party components

This source package adds a small HTTP adapter; third-party packages are installed from npm/PyPI by the Docker build rather than copied into this source package. Preserve their installed license files and notices when building or redistributing containers. Do not delete package metadata/licenses to reduce image size.

- REA / `rea-agents` 6.7.0: MIT. Copy retained in `licenses/REA-MIT.txt`. Source: https://github.com/morluto/rea .
- pwntools 4.15.0: upstream metadata says mostly MIT with GPL/BSD portions; see the full retained `LICENSE-pwntools.txt`, including component notices. Source: https://github.com/Gallopsled/pwntools/tree/4.15.0 .
- pyelftools 0.33: public-domain dedication/license retained in `licenses/pyelftools-LICENSE`. Source: https://github.com/eliben/pyelftools .
- Unicorn 2.1.2: do not infer the native engine's terms from the Python wheel's BSD metadata. The upstream native engine includes GPL-2.0 licensing and component-specific terms; see https://github.com/unicorn-engine/unicorn/blob/2.1.2/COPYING and the source at https://github.com/unicorn-engine/unicorn/tree/2.1.2 . Preserve applicable notices and satisfy source-distribution obligations before redistributing a binary image. No Unicorn binary is included in this source package.
- Capstone 5.0.3: BSD-style component license retained in `licenses/capstone-LICENSE.txt`; source: https://github.com/capstone-engine/capstone .
- Additional Node/Python transitive dependencies are enumerated by `package-lock.json` and `requirements.lock`; their own installed metadata/license texts apply. The Debian base, Node and Python also have their own notices and licenses.

No Hopper, IDA, Ghidra or proprietary native engine is bundled. This document identifies relevant upstream terms; it is not a claim that all dependencies share one license or that redistribution obligations have been discharged merely by linking source repositories.
