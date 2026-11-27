# Development Guide

This guide covers setting up a development environment for XTM Composer and contributing to the project.

XTM Composer is the container-based Integration Manager of OpenCTI: it deploys and manages, on your orchestrator, the connectors that you set up from the platform. To install, configure and use it, see the [Integration Manager](../deployment/integration-manager.md) pages, and the [Configuration](../deployment/integration-manager/configuration.md) reference for every setting used below.

## Prerequisites

### Required Tools

- **Rust**: 1.85.0 or higher (the crate uses the 2024 edition; the release image is built with Rust 1.96)
- **Git**: For version control
- **Docker**: For testing orchestration features
- **OpenSSL**: For generating RSA keys

### Recommended Tools

- **IntelliJ IDEA** with Rust Plugin
- **cargo-watch**: For auto-reloading during development
- **cargo-clippy**: For linting
- **cargo-fmt**: For code formatting

## Setting Up Development Environment

### 1. Install Rust

```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### 2. Clone Repository

```bash
git clone https://github.com/FiligranHQ/xtm-composer.git
cd xtm-composer
```

### 3. Install Development Dependencies

```bash
# Install cargo-watch for auto-reloading
cargo install cargo-watch

# Install clippy for linting
rustup component add clippy

# Install rustfmt for formatting
rustup component add rustfmt
```

### 4. Generate Development Keys

```bash
# Generate RSA private key for development (PKCS#8 format, as required by XTM Composer)
openssl genpkey -algorithm RSA -out private_key_4096.pem -pkeyopt rsa_keygen_bits:4096
```

### 5. Create Development Configuration

Create `config/development.yaml`:

```yaml
manager:
  id: dev-manager-${USER}  # Unique ID for your dev instance
  credentials_key_filepath: ./private_key_4096.pem
  logger:
    level: debug
    format: pretty
    directory: true
    console: true
  debug:
    show_env_vars: true
    show_sensitive_env_vars: false  # Set to true if debugging auth issues

opencti:
  enable: true
  url: http://host.docker.internal:4000  # Your local OpenCTI instance
  token: your-dev-token
  daemon:
    selector: docker
    docker:
      network_mode: bridge
```

## Running in Development

### Basic Development Run

```bash
# Set development environment
export COMPOSER_ENV=development

# Run with cargo
cargo run

# Or with auto-reload on file changes
cargo watch -x run
```

### Running with Environment Variables

```bash
COMPOSER_ENV=development \
MANAGER__ID=dev-test \
OPENCTI__URL=http://localhost:4000 \
OPENCTI__TOKEN=your-token \
cargo run
```

### Debug Output

Enable detailed debug output:

```bash
# Set log level to trace
export MANAGER__LOGGER__LEVEL=trace

# Show environment variables at startup
export MANAGER__DEBUG__SHOW_ENV_VARS=true

# Run with backtrace for errors
RUST_BACKTRACE=1 cargo run
```

## Project Structure

```
xtm-composer/
├── src/
│   ├── main.rs              # Application entry point
│   ├── api/                 # External API integrations
│   │   ├── opencti/         # OpenCTI API client
│   │   └── openaev/         # OpenAEV API client
│   ├── config/              # Configuration management
│   │   ├── mod.rs
│   │   └── settings.rs      # Settings structure definitions
│   ├── engine/              # Core business logic
│   │   ├── mod.rs
│   │   ├── opencti.rs       # OpenCTI engine
│   │   └── openaev.rs       # OpenAEV engine
│   ├── orchestrator/        # Container orchestration
│   │   ├── mod.rs
│   │   ├── docker/          # Docker implementation
│   │   ├── kubernetes/      # Kubernetes implementation
│   │   ├── podman/          # Podman implementation
│   │   ├── portainer/       # Portainer implementation
│   │   └── swarm/           # Docker Swarm implementation
│   └── system/              # System signal handling
├── api/                     # GraphQL schema used to generate the OpenCTI client
├── config/                  # Configuration files
│   ├── default.yaml         # Default configuration
│   └── development.yaml     # Development overrides (you create it, ignored by Git)
├── Cargo.toml               # Rust dependencies
└── build.rs                 # Build script
```

## Development Workflow

### 1. Feature Development

```bash
# Create feature branch
git switch -c feature/your-feature-name

# Make changes and test
cargo build
cargo test

# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Commit changes
git add .
git commit -m "[composer] Add your feature description (#issue)"
```

### 2. Building

```bash
# Development build (with debug symbols)
cargo build

# Release build (optimized)
cargo build --release

# Check compilation without building
cargo check
```

## Code Style Guidelines

### Rust Best Practices

1. **Follow Rust naming conventions**:
   - Use `snake_case` for functions and variables
   - Use `PascalCase` for types and traits
   - Use `SCREAMING_SNAKE_CASE` for constants

2. **Error Handling**:
   - Use `Result<T, E>` for recoverable errors
   - Use `panic!` only for unrecoverable errors
   - Provide meaningful error messages

3. **Documentation**:
   - Add doc comments (`///`) for public APIs
   - Include examples in documentation
   - Document panics and errors

### Example Code Style

```rust
/// Manages connector lifecycle in OpenCTI
///
/// # Examples
///
/// ```
/// let manager = ConnectorManager::new(config)?;
/// manager.start()?;
/// ```
pub struct ConnectorManager {
    config: ManagerConfig,
    orchestrator: Box<dyn Orchestrator>,
}

impl ConnectorManager {
    /// Creates a new connector manager
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid
    pub fn new(config: ManagerConfig) -> Result<Self, ManagerError> {
        // Implementation
    }
}
```

## Testing with Local Services

### Running Local OpenCTI

The `opencti-dev` Docker Compose file of the OpenCTI repository starts the dependencies of the platform (Elasticsearch, Redis, RabbitMQ, S3 storage), not OpenCTI itself. Run the back end from the source code, as described in [Platform development](platform.md):

```bash
# Clone OpenCTI
git clone https://github.com/OpenCTI-Platform/opencti.git

# Start the dependencies
cd opencti/opencti-platform/opencti-dev
docker compose up -d

# Create your development configuration
cd ../opencti-graphql
cp config/default.json config/development.json
```

OpenCTI has no default password: the back end does not start while the admin password or token keeps its `ChangeMe` value. In the `app.admin` section of `config/development.json`, set the admin password, and set the admin token to a UUID or an OpenCTI formatted token:

```json
"admin": {
  "email": "admin@opencti.io",
  "password": "<your admin password>",
  "token": "<a UUID, for example the output of uuidgen or an OpenCTI formatted token>"
}
```

Then install the Node.js dependencies and start the back end (`yarn install`, then `yarn start` in `opencti-graphql`), as described in [Platform development](platform.md). The API is available at `http://localhost:4000/graphql`. To use the web interface, start the front end too, then log in with the admin email and the password that you set. For a local test, set `opencti.token` (`OPENCTI__TOKEN`) of XTM Composer to the admin token.

### Running Local Docker Registry

```bash
# Start local registry for testing
docker run -d -p 5000:5000 --name registry registry:2

# Tag and push test images
docker tag your-image localhost:5000/your-image
docker push localhost:5000/your-image
```

## Debugging


### Using IntelliJ IDEA

1. **Install IntelliJ Rust Plugin**:
   - Open IntelliJ IDEA
   - Go to `File > Settings` (or `IntelliJ IDEA > Preferences` on macOS)
   - Navigate to `Plugins`
   - Search for "Rust" and install the official JetBrains Rust plugin
   - Restart IntelliJ IDEA

2. **Open the Project**:
   - Use `File > Open` and select the `xtm-composer` directory
   - IntelliJ will automatically detect the Cargo.toml file

3. **Using .run Configuration Files**:
   
   The project already includes IntelliJ run configurations in the `dev/` directory:
   - `dev/Run xtm-composer.run.xml` - For running the application
   - `dev/Test xtm-composer.run.xml` - For running tests
   
   These should be automatically detected by IntelliJ.

4. **Set Breakpoints and Debug**:
   - Click in the gutter next to line numbers to set breakpoints
   - Use `Run > Debug 'Debug XTM Composer'` or click the debug icon
   - Use the debug panel to step through code, inspect variables, etc.

5. **Additional IntelliJ Settings**:
   - Enable format on save: `Settings > Tools > Actions on Save > Reformat code`
   - Configure Rust fmt: `Settings > Languages & Frameworks > Rust > Rustfmt`
   - Enable Clippy: `Settings > Languages & Frameworks > Rust > External Linters`

### Common Issues

#### 1. Connection Refused

```bash
# Check that OpenCTI is running and accepts your token (queries must use POST)
curl -X POST http://localhost:4000/graphql \
  -H "Authorization: Bearer <your token>" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ about { version } }"}'

# Check Docker daemon
docker info
```

#### 2. Compilation Errors

```bash
# Clean build artifacts
cargo clean

# Update dependencies
cargo update

# Check for breaking changes
cargo check
```

## Contributing

For detailed information about contributing to XTM Composer, including:
- Commit message format and conventions
- Pull request process
- Code of conduct
- Testing requirements
- GPG signing setup

Please refer to our [**Contributing Guide**](https://github.com/FiligranHQ/xtm-composer/blob/master/CONTRIBUTING.md).

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [OpenCTI Documentation](https://docs.opencti.io)
- [Docker Documentation](https://docs.docker.com)
- [Kubernetes Documentation](https://kubernetes.io/docs)
