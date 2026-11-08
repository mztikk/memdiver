# Library to read and write memory of an external process

We're building a production-grade Library to read and write memory of an external process for Windows and Linux. This is professional-grade software that needs to be stable, fully-tested and real-world deployable. No Shortcuts or toy-project - solid as a rock.

## Dev Workflow
- Ask questions only when absolutely necessary - work autonomously
- Start by asking questions to determine Library name. Suggest a few
- Testing is of the utmost importance - use lots unit tests and run automated testing
- Do things properly, this is production-grade software and not a toy project
- Create AGENTS.md and relevant skills to support development, and contain concrete development guidelines
- idiomatic rust
- standards
- Commit and push to [repo](https://github.com/mztikk/external-memory-dsh) . IMPORTANT: do a Code Review before every commit and make sure all changes comply with code style, production-grade quality standards and everything has been tested and has unit tests that have passed where necessary

## Tech stack
- Rust
- Justfile

## Basic Architecture
- Cargo workspace
- Build as modular as possible and create separate crates
