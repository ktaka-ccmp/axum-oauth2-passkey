# Architecture blueprint

## Overview

The following is a blueprint of the architecture of this application. It reflects the current state of the application with proposed consolidation of components.

## Current Components

- demo-integrated: example of axum application that uses oauth2 and passkey authentication
- libaxum: provides oauth2 and passkey authentication handlers for axum application
- libauth: public interface to provide oauth2 and passkey authentication. Also acts as authentication coordination layer.
  - liboauth2: oauth2 operations, stores oauth2 accounts. refers user_id from libuserdb
  - libpasskey: passkey operations, stores passkey credentials. refers user_id from libuserdb
  - libsession: manages session using cache store, provides session cookie. refers user_id from libuserdb
  - libstorage: cache & operation provider, SQL store provider
- libuserdb(replaceable): user_id provider

## Proposed Consolidation

To simplify the architecture and reduce dependencies, we propose the following consolidation:

- demo-integrated: remains as is
- libaxum: remains as is
- libauth: becomes the main public interface with internal modules
  - auth::oauth2: (formerly liboauth2) internal module for oauth2 operations
  - auth::passkey: (formerly libpasskey) internal module for passkey operations
  - auth::session: (formerly libsession) internal module for session management
  - auth::storage: (formerly libstorage) internal module for storage operations
- libuserdb: remains separate as it's designed to be replaceable

## Benefits of Consolidation

- Simplified dependency management
- Easier maintenance with related code in one place
- Reduced boilerplate for inter-module communication
- Better encapsulation of internal implementation details
- Smaller dependency footprint for users of the library

## Notes

- libuserdb remains replaceable, allowing for alternative user_id providers or external REST APIs
- The consolidated approach maintains logical separation of concerns while reducing crate boundaries

## Analysis of the codebase as of 202503171800

### Component Structure Verification

The codebase correctly follows the architecture outlined in the "Current Components" section:

1. **libauth**: Acts as the coordination layer between different authentication mechanisms
   - Provides public interfaces through `OAuth2Coordinator` and `PasskeyCoordinator`
   - Initializes all required stores and handles errors appropriately

2. **liboauth2**: Handles OAuth2 operations
   - Manages OAuth2 accounts in its own database tables
   - References user_id from libuserdb as specified
   - Properly exports necessary types and functions

3. **libpasskey**: Manages passkey credentials
   - Stores passkey credentials with references to user_id
   - Provides authentication and registration functionality
   - Correctly exports necessary types

4. **libsession**: Manages session using cache store
   - Provides session cookie functionality
   - References user_id from libuserdb

5. **libstorage**: Provides storage solutions
   - Offers SQL store provider functionality
   - Used by other components for database operations

6. **libuserdb**: Acts as the user_id provider
   - Manages user data independently
   - No longer contains OAuth2 account functionality (correctly moved)

7. **libaxum**: Provides handlers for axum applications
   - Correctly implements OAuth2 and passkey authentication routes
   - Uses the coordination layer (libauth) appropriately

### Dependency Structure

The dependencies between components are correctly implemented:

- libauth depends on liboauth2, libpasskey, libuserdb, and libstorage
- liboauth2 and libpasskey depend on libstorage but not on each other
- libuserdb depends on libstorage but not on liboauth2 or libpasskey
- libaxum depends on all the libraries to provide its handlers

### Identified Issues

1. **Incomplete Passkey Coordinator Implementation**:
   - The `PasskeyCoordinator::get_credentials_by_user_id` method returns an empty vector with a comment indicating it's a placeholder
   - This could lead to issues if any code relies on this method returning actual credentials

2. **Counter Verification in Passkey Authentication**:
   - The counter verification in `libpasskey/src/passkey/auth.rs` is fully implemented and working correctly
   - The implementation properly checks if the counter is supported, verifies it has increased, and updates the stored counter value after successful verification
   - The code correctly handles potential cloning attacks by detecting decreased counter values

3. **WebAuthn Terminology**:
   - The codebase maintains backward compatibility by using both older terminology ("resident key", "require_resident_key") and newer terminology ("discoverable credential")
   - Comments and documentation acknowledge the updated terminology from WebAuthn Level 2 specification
   - This approach is appropriate for maintaining compatibility with existing authenticators and client libraries

4. **Error Handling Consistency** (to be addressed during consolidation):
   - Some components use `thiserror` for error handling while others use custom error types
   - This would be best addressed during the consolidation of libraries into `libauth`
   - Standardizing on `thiserror` across all components would improve consistency

5. **Potential Circular Dependency Risk** (to be addressed during consolidation):
   - While the current implementation avoids circular dependencies, the coordination layer (libauth) depends on all other components
   - The proposed consolidation would naturally resolve this by placing all components under a single crate with proper module boundaries

### Conclusion

The recent refactoring to move OAuth2Account-related functionality from libuserdb to liboauth2 has been successfully implemented, and the separation of concerns is maintained. The proposed consolidation approach would further simplify the codebase by reducing the number of separate crates while maintaining logical separation through modules.
