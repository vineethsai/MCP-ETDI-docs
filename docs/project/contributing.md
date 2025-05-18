# Contributing Guidelines

Thank you for your interest in contributing to the Enhanced Tool Definition Interface (ETDI) project! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Documentation Guidelines](#documentation-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Community](#community)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

We are committed to providing a friendly, safe, and welcoming environment for all, regardless of gender, sexual orientation, ability, ethnicity, socioeconomic status, and religion (or lack thereof).

## How Can I Contribute?

There are many ways to contribute to ETDI:

### Reporting Bugs

- Use the issue tracker to report bugs
- Check if the bug has already been reported
- Use the bug report template
- Include detailed steps to reproduce the bug
- Provide system information and context

### Suggesting Enhancements

- Use the issue tracker to suggest enhancements
- Check if the enhancement has already been suggested
- Use the feature request template
- Describe the current behavior and the expected behavior
- Explain why this enhancement would be useful

### Code Contributions

- Check the [Implementation Tracker](effort-tracker.md) for tasks
- Look for issues labeled "good first issue" or "help wanted"
- Discuss major changes in an issue before implementing
- Follow the [Development Workflow](#development-workflow)

### Documentation

- Improve existing documentation
- Create new documentation
- Fix documentation bugs
- Add examples and use cases

### Testing

- Write unit tests
- Conduct integration tests
- Perform security testing
- Report test results

## Development Workflow

### Setting Up the Development Environment

1. Fork the repository
2. Clone your fork locally
3. Install dependencies:

```bash
npm install
```

4. Set up development tools:

```bash
npm run setup-dev
```

### Making Changes

1. Create a new branch for your changes:

```bash
git checkout -b feature/your-feature-name
```

2. Make your changes
3. Run tests to ensure your changes don't break existing functionality:

```bash
npm test
```

4. Run linters to ensure code quality:

```bash
npm run lint
```

5. Commit your changes with a clear commit message:

```bash
git commit -m "Add feature: your feature description"
```

### Branch Naming Convention

- `feature/` - for new features
- `bugfix/` - for bug fixes
- `docs/` - for documentation changes
- `test/` - for test additions or modifications
- `refactor/` - for code refactoring
- `perf/` - for performance improvements

### Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line
- Consider using the conventional commits format:
  - `feat:` for features
  - `fix:` for bug fixes
  - `docs:` for documentation
  - `test:` for tests
  - `refactor:` for refactoring
  - `perf:` for performance improvements
  - `chore:` for maintenance tasks

## Pull Request Process

1. Update the README.md or documentation with details of changes if applicable
2. Update the [Implementation Tracker](effort-tracker.md) if applicable
3. Ensure all tests pass and code meets quality standards
4. Submit a pull request to the `main` branch
5. The pull request will be reviewed by maintainers
6. Address any feedback from the code review
7. Once approved, the pull request will be merged

### Pull Request Template

When creating a pull request, please use the provided template that includes:

- A description of the changes
- Related issue number(s)
- Type of change (bugfix, feature, etc.)
- Checklist of completed items
- Testing information
- Screenshots (if applicable)

## Coding Standards

### TypeScript

- Use TypeScript for all new code
- Follow the established coding style
- Use strict typing
- Document public APIs with JSDoc comments
- Use meaningful variable and function names
- Keep functions small and focused
- Avoid any and use proper types

### Style Guide

- Use 2 spaces for indentation
- Use single quotes for strings
- Use semicolons
- Use camelCase for variables and functions
- Use PascalCase for classes and interfaces
- Use interfaces for object shapes
- Use enums for fixed sets of values
- Use async/await instead of promises
- Limit line length to 100 characters
- Add trailing commas in arrays and objects

### Code Quality

- Run linters before submitting code:

```bash
npm run lint
```

- Fix any linting issues:

```bash
npm run lint:fix
```

- Follow best practices for security
- Handle errors properly
- Add appropriate logging
- Consider edge cases

## Documentation Guidelines

### Code Documentation

- Use JSDoc for all public APIs
- Document parameters, return values, and exceptions
- Provide examples where appropriate
- Update documentation when changing functionality

### Project Documentation

- Keep the README.md up to date
- Document new features
- Create/update user guides
- Provide examples and tutorials
- Use clear and concise language
- Include diagrams when helpful

## Testing Guidelines

### Unit Testing

- Write unit tests for all new functionality
- Use Jest for testing
- Aim for high test coverage
- Test edge cases and error conditions
- Mock external dependencies

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run specific tests
npm test -- -t "test name pattern"
```

### Security Testing

- Consider security implications of your changes
- Test for common vulnerabilities
- Review for potential security issues
- Document security considerations

## Community

### Communication Channels

- GitHub Issues: For bug reports, feature requests, and discussions
- Community Forum: For general questions and discussions
- Developer Chat: For real-time collaboration

### Becoming a Maintainer

Contributors who have made significant and valuable contributions may be invited to become maintainers. Maintainers have additional responsibilities and privileges, including:

- Reviewing pull requests
- Merging approved pull requests
- Managing issues
- Contributing to project direction

### Recognition

All contributors will be recognized in the project's contributors list. We value all contributions, regardless of size or type.

## Thank You!

Thank you for contributing to ETDI! Your efforts help make this project better for everyone. 