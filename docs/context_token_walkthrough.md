# Session Boundary Protection with Context Tokens

This document explains how the context token mechanism works to prevent session desynchronization issues in the authentication system.

## Overview

The system uses a dual approach to prevent session boundary issues:

1. **Explicit Registration Modes**
   - Explicit registration modes: `RegistrationMode::AddToExistingUser` and `RegistrationMode::NewUser`
   - Separate handlers for different authentication operations

2. **Signed Context Tokens for Session/Page Synchronization**
   - Tokens contain obfuscated user_id, expiration, and signature
   - Delivered via HTTP cookies
   - Page context embedded in HTML/JavaScript
   - Stateless implementation requiring no additional storage

## Implementation Details

### Context Token Structure

A context token is a string with the format: `obfuscated_user_id:expiration:signature` where:

- `obfuscated_user_id` is a HMAC-SHA256 hash of the user ID
- `expiration` is a Unix timestamp indicating when the token expires (1 day by default)
- `signature` is a HMAC-SHA256 signature of `obfuscated_user_id:expiration` using a server-side secret

### Flow for Authentication and Adding a Passkey

1. **User Login**
   - When a user logs in (via OAuth2 or passkey), the system:
     - Creates a session cookie
     - Creates a context token cookie with the same user ID
     - Both cookies are delivered to the client
     - The obfuscated user ID is also embedded in the page as `PAGE_USER_CONTEXT`

2. **Adding a Passkey to an Existing User**
   - Client initiates passkey registration with `mode: 'add_to_existing_user'`
   - Client submits the passkey data along with the page context
   - Server extracts the context token from cookies
   - Server verifies that:
     - The context token is valid and not expired
     - The token's obfuscated user ID matches the session user's obfuscated ID
     - The page context matches the obfuscated user ID
   - If verification passes, the passkey is associated with the user
   - If verification fails (e.g., user session changed), an error is returned

3. **Creating a New User with a Passkey**
   - Client initiates passkey registration with `mode: 'new_user'`
   - Client submits the passkey data to the server
   - Server creates a new user account with the passkey
   - Server sets both session and context token cookies for the new user

### Implementation in Code

The context token functionality is implemented in `oauth2_passkey/src/session/main/context_token.rs` with these key functions:

- `obfuscate_user_id` - Hashes the user ID to prevent direct exposure
- `generate_user_context_token` - Creates a signed token for a user
- `verify_user_context_token` - Validates a token's signature, expiration, and user ID
- `create_context_token_cookie` - Creates HTTP headers with the token cookie
- `extract_context_token_from_cookies` - Extracts the token from request cookies
- `verify_context_token_and_page` - Verifies both cookie token and page context

## Security Considerations

- User IDs are obfuscated using HMAC-SHA256 to prevent direct exposure
- Context tokens are signed using HMAC-SHA256 to prevent tampering
- Tokens include an expiration timestamp to limit their validity period
- Tokens are delivered via HttpOnly cookies to prevent access via JavaScript
- The verification process ensures the user who loaded the page is the same as the user sending the request
- The server secret is configurable via the `AUTH_SERVER_SECRET` environment variable
- The feature can be toggled with the `USE_CONTEXT_TOKEN_COOKIE` environment variable

## Testing

You can test the context token mechanism by:

1. Logging in as User A
2. Opening a new passkey registration page
3. In a different tab or browser, logging out and logging in as User B
4. Returning to the registration page and attempting to complete registration
5. The system should reject the operation because the context token still contains User A's ID

This protection mechanism helps prevent confused deputy problems and session desynchronization issues in multi-tab or shared browser scenarios.
