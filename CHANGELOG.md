## [0.1.1]

### Fixed
- Authentication: Replaced Exception raises with None returns in the Auth class. This allows DRF to properly cycle through multiple authentication classes if one fails.
- Settings: Removed import_string validation from settings. This prevents AppRegistryNotReady errors caused by attempting to load classes before Django has fully initialized.
- Session Service: Added **kwargs support to SessionService creation methods. This provides the flexibility needed to handle custom fields when using a swapped or extended Session model.

## [0.1.0]

### Added
- `drf-sessions` initial release.
