# Contributing to Rust Tree-sitter Agent Code Utility

Thank you for your interest in contributing to this project! We welcome contributions from the community and are pleased to have you join us.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/rust-treesitter-agent-code-utility.git
   cd rust-treesitter-agent-code-utility
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** and test them
5. **Commit your changes** using conventional commits
6. **Push to your fork** and create a pull request

## 🛠️ Development Setup

### Prerequisites
- Rust 1.70+ (latest stable recommended)
- Git
- A code editor (VS Code, IntelliJ IDEA, or similar)

### Building the Project
```bash
# Build the library
cargo build

# Build the CLI
cargo build --bin tree-sitter-cli

# Run tests
cargo test

# Run examples
cargo run --example basic_usage
cargo run --example analyze_codebase -- ./src
```

### Running the CLI
```bash
# Build and run
cargo run --bin tree-sitter-cli -- --help

# Or build release and use directly
cargo build --release --bin tree-sitter-cli
./target/release/tree-sitter-cli --help
```

## 📝 Contribution Guidelines

### Code Style
- Follow standard Rust formatting: `cargo fmt`
- Ensure code passes linting: `cargo clippy`
- Write comprehensive tests for new features
- Document public APIs with doc comments
- Use meaningful variable and function names

### Commit Messages
We use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(cli): add new map command for visual code structure
fix(parser): handle edge case in incremental parsing
docs(readme): update installation instructions
test(analyzer): add tests for symbol extraction
```

### Pull Request Process

1. **Ensure your code builds and all tests pass**:
   ```bash
   cargo test
   cargo clippy
   cargo fmt --check
   ```

2. **Update documentation** if you've changed APIs

3. **Add tests** for new functionality

4. **Update CHANGELOG.md** if applicable

5. **Create a clear PR description** explaining:
   - What changes you made
   - Why you made them
   - How to test the changes
   - Any breaking changes

### Testing
- Write unit tests for individual functions
- Write integration tests for complex workflows
- Test CLI commands with various inputs
- Ensure examples still work

### Documentation
- Update README.md for new features
- Update CLI_README.md for CLI changes
- Add doc comments for public APIs
- Include examples in documentation

## 🎯 Areas for Contribution

### High Priority
- **Language Support**: Add support for more programming languages
- **Query Patterns**: Expand tree-sitter query patterns
- **Performance**: Optimize parsing and analysis performance
- **CLI Features**: Add new analysis commands and options

### Medium Priority
- **Documentation**: Improve examples and tutorials
- **Testing**: Increase test coverage
- **Error Handling**: Improve error messages and recovery
- **Configuration**: Add configuration file support

### Good First Issues
- Fix typos in documentation
- Add more examples
- Improve error messages
- Add unit tests for existing functions
- Update dependencies

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment information**:
   - Rust version (`rustc --version`)
   - Operating system
   - Project version

2. **Steps to reproduce** the issue

3. **Expected behavior** vs **actual behavior**

4. **Minimal code example** if applicable

5. **Error messages** or logs

## 💡 Feature Requests

For feature requests, please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** and motivation
3. **Provide examples** of how it would be used
4. **Consider implementation** complexity
5. **Discuss alternatives** you've considered

## 📚 Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Tree-sitter Documentation](https://tree-sitter.github.io/tree-sitter/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)

## 🤝 Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and inclusive in all interactions.

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the same terms as the project (Apache 2.0 or MIT).

## 🙏 Recognition

Contributors will be recognized in:
- The project README
- Release notes for significant contributions
- The project's contributor list

Thank you for contributing to make this project better! 🚀
