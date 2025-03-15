// Base64 utility functions

// Global state to track ongoing operations
const passKeyState = {
    isAuthenticating: false,
    isRegistering: false,
    // Track retry attempts
    authRetryCount: 0,
    regRetryCount: 0,
    // Maximum number of retries
    maxRetries: 3,
    // Timeout for network operations in milliseconds
    networkTimeout: 15000,
    // Track current authentication controller to allow cancellation
    currentAuthController: null,
    // Track current registration controller to allow cancellation
    currentRegController: null
};
function arrayBufferToBase64URL(buffer) {
    if (!buffer) return null;
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) {
        str += String.fromCharCode(byte);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLToUint8Array(base64URL) {
    if (!base64URL) return null;
    const padding = '='.repeat((4 - base64URL.length % 4) % 4);
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

// Authentication functions
async function startAuthentication(withUsername = false) {
    // If authentication is already in progress, cancel it and start a new one
    if (passKeyState.isAuthenticating) {
        console.log('Cancelling previous authentication attempt and starting a new one');
        // Reset state before starting a new authentication
        passKeyState.isAuthenticating = false;
        passKeyState.authRetryCount = 0;
        updateAuthButtonState(false);
        // Small delay to ensure UI updates before starting new authentication
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    const authStatus = document.getElementById("auth-status");
    const authActions = document.getElementById("auth-actions");

    try {
        // Set authenticating state and update UI
        passKeyState.isAuthenticating = true;
        updateAuthButtonState(true);
        const startResponse = await fetchWithTimeout(PASSKEY_ROUTE_PREFIX + '/auth/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: "{}"
        }, passKeyState.networkTimeout, true);

        if (!startResponse.ok) {
            const errorText = await startResponse.text();
            alert('Authentication failed: ' + errorText);
            passKeyState.isAuthenticating = false;
            updateAuthButtonState(false);
            return;
        }

        const options = await startResponse.json();
        console.log('Raw Authentication options:', options);

        // Convert base64url strings
        options.challenge = base64URLToUint8Array(options.challenge);
        if (options.allowCredentials && Array.isArray(options.allowCredentials)) {
            console.log('Raw credentials:', options.allowCredentials);
            options.allowCredentials = options.allowCredentials.map(credential => ({
                type: 'public-key',  // Required by WebAuthn
                id: new Uint8Array(credential.id),
                transports: credential.transports  // Optional
            }));
            console.log('Processed credentials:', options.allowCredentials);
        } else {
            options.allowCredentials = [];
        }
        console.log('Processed Authentication options:', options);

        // options.rpId = "amazon.co.jp"

        const credential = await navigator.credentials.get({
            publicKey: options
        });

        console.log('Authentication credential:', credential);

        const authResponse = {
            auth_id: options.authId,
            id: credential.id,
            raw_id: arrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            authenticator_attachment: credential.authenticatorAttachment,
            response: {
                authenticator_data: arrayBufferToBase64URL(credential.response.authenticatorData),
                client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON),
                signature: arrayBufferToBase64URL(credential.response.signature),
                user_handle: arrayBufferToBase64URL(credential.response.userHandle)
            },
        };

        console.log('Authentication response:', authResponse);

        const verifyResponse = await fetchWithTimeout(PASSKEY_ROUTE_PREFIX + '/auth/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authResponse)
        }, passKeyState.networkTimeout, true);

        if (!verifyResponse.ok) {
            console.error('Authentication failed:', verifyResponse.status, verifyResponse.statusText);
            const errorText = await verifyResponse.text();
            alert('Authentication failed: ' + errorText);
            passKeyState.isAuthenticating = false;
            updateAuthButtonState(false);
            return;
        }

        // Response is OK, handle success
        setTimeout(() => {
            window.location.reload();
        }, 100);  // Wait for 0.1 second before reloading

        verifyResponse.text().then(function(text) {
            if (authStatus) {
                authStatus.textContent = `Welcome back ${text}!`;
            }
        });
    } catch (error) {
        console.error('Error during authentication:', error);
        
        // Handle network errors with retry logic
        if (error.name === 'AbortError' || error.name === 'TypeError' || error.message.includes('network')) {
            if (passKeyState.authRetryCount < passKeyState.maxRetries) {
                console.log(`Network error during authentication. Retrying (${passKeyState.authRetryCount + 1}/${passKeyState.maxRetries})...`);
                passKeyState.authRetryCount++;
                // Wait a moment before retrying
                setTimeout(() => startAuthentication(withUsername), 1000);
                return;
            } else {
                alert('Authentication failed due to network issues. Please check your connection and try again.');
            }
        } else {
            alert('Authentication failed: ' + error.message);
        }
        
        // Reset state
        passKeyState.isAuthenticating = false;
        passKeyState.authRetryCount = 0;
        updateAuthButtonState(false);
    }
}

function createRegistrationModal() {
    // Create modal container if it doesn't exist
    let modal = document.getElementById('registration-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'registration-modal';
        modal.className = 'modal';
        modal.style.cssText = 'display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);';

        modal.innerHTML = `
            <h3>Register New Passkey</h3>
            <div style="margin: 10px 0;">
                <input type="text" id="reg-username" placeholder="Username" style="width: 100%; margin-bottom: 10px; padding: 5px;">
                <input type="text" id="reg-displayname" placeholder="Display Name" style="width: 100%; padding: 5px;">
            </div>
            <div style="text-align: right;">
                <button onclick="closeRegistrationModal()">Cancel</button>
                <button onclick="submitRegistration()">Register</button>
            </div>
        `;

        document.body.appendChild(modal);
    }
    return modal;
}

function showRegistrationModal() {
    const modal = createRegistrationModal();
    modal.style.display = 'block';
    
    // Set default values immediately
    document.getElementById('reg-username').value = 'username';
    document.getElementById('reg-displayname').value = 'displayname';

    // Try to get current user info to pre-fill the form
    fetch('/summary/user-info', {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        }
        // If not logged in or error, keep the default values
        return null;
    })
    .then(userData => {
        if (userData) {
            // Pre-fill the form with user data
            document.getElementById('reg-username').value = userData.account ? `${userData.account}#${userData.passkey_count + 1}` : 'username';
            document.getElementById('reg-displayname').value = userData.label ? `${userData.label}#${userData.passkey_count + 1}` : 'displayname';
        }
    })
    .catch(error => {
        console.error('Error fetching user data:', error);
        // Default values already set, so no action needed
    });
}

function closeRegistrationModal() {
    const modal = document.getElementById('registration-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Update authentication button state
function updateAuthButtonState(isAuthenticating) {
    const authButton = document.querySelector('.auth-button');
    if (authButton) {
        if (isAuthenticating) {
            authButton.disabled = true;
            authButton.textContent = 'Authenticating...';
        } else {
            authButton.disabled = false;
            authButton.textContent = 'Authenticate with Passkey';
        }
    }
}

async function submitRegistration() {
    const username = document.getElementById('reg-username').value.trim();
    const displayname = document.getElementById('reg-displayname').value.trim();

    if (!username || !displayname) {
        alert('Both username and display name are required');
        return;
    }

    closeRegistrationModal();
    await startRegistration(username, displayname);
}

async function startRegistration(username = null, displayname = null) {
    // If registration is already in progress, cancel it and start a new one
    if (passKeyState.isRegistering) {
        console.log('Cancelling previous registration attempt and starting a new one');
        // Reset state before starting a new registration
        passKeyState.isRegistering = false;
        passKeyState.regRetryCount = 0;
        updateRegButtonState(false);
        // Small delay to ensure UI updates before starting new registration
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    try {
        // Set registering state and update UI
        passKeyState.isRegistering = true;
        updateRegButtonState(true);
        let startResponse;
        startResponse = await fetchWithTimeout(PASSKEY_ROUTE_PREFIX + '/register/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, displayname })
        }, passKeyState.networkTimeout, false);

        if (!startResponse.ok) {
            const errorText = await startResponse.text();
            alert('Registration failed: ' + errorText);
            passKeyState.isRegistering = false;
            updateRegButtonState(false);
            return;
        }

        const options = await startResponse.json();
        console.log('Registration options:', options);

        // Convert base64url strings to Uint8Array
        let userHandle = options.user.user_handle;
        options.challenge = base64URLToUint8Array(options.challenge);
        options.user.id = new TextEncoder().encode(userHandle); // Convert user_handle to Uint8Array and set to user.id

        console.log('Registration options:', options);
        console.log('Registration user handle:', userHandle);

        const credential = await navigator.credentials.create({
            publicKey: options
        });

        // console.log('Registration credential:', credential);
        // console.log('Registration credential response clientDataJSON:', credential.response.clientDataJSON);

        const credentialResponse = {
            id: credential.id,
            raw_id: arrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                attestation_object: arrayBufferToBase64URL(credential.response.attestationObject),
                client_data_json: arrayBufferToBase64URL(credential.response.clientDataJSON)
            },
            user_handle: userHandle,
            // username: username
        };

        console.log('Registration response:', credentialResponse);

        const finishResponse = await fetchWithTimeout(PASSKEY_ROUTE_PREFIX + '/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialResponse)
        }, passKeyState.networkTimeout, false);

        if (finishResponse.ok) {
            location.reload(); // Refresh to show authenticated state
        } else {
            throw new Error('Registration verification failed');
        }
    } catch (error) {
        console.error('Error during registration:', error);
        
        // Handle network errors with retry logic
        if (error.name === 'AbortError' || error.name === 'TypeError' || error.message.includes('network')) {
            if (passKeyState.regRetryCount < passKeyState.maxRetries) {
                console.log(`Network error during registration. Retrying (${passKeyState.regRetryCount + 1}/${passKeyState.maxRetries})...`);
                passKeyState.regRetryCount++;
                // Wait a moment before retrying
                setTimeout(() => startRegistration(username, displayname), 1000);
                return;
            } else {
                alert('Registration failed due to network issues. Please check your connection and try again.');
            }
        } else {
            alert('Registration failed: ' + error.message);
        }
        
        // Reset state
        passKeyState.isRegistering = false;
        passKeyState.regRetryCount = 0;
        updateRegButtonState(false);
    }
}

// Update registration button state
// Helper function for fetch with timeout to handle network transitions
async function fetchWithTimeout(url, options, timeout, isAuth = false) {
    // Create a new controller for this request
    const controller = new AbortController();
    const signal = controller.signal;
    
    // Store the controller in the global state to allow cancellation
    if (isAuth) {
        // If there's an existing controller, abort it
        if (passKeyState.currentAuthController) {
            try {
                passKeyState.currentAuthController.abort();
            } catch (e) {
                console.log('Error aborting previous controller:', e);
            }
        }
        passKeyState.currentAuthController = controller;
    } else if (url.includes('/register/')) {
        // If there's an existing controller, abort it
        if (passKeyState.currentRegController) {
            try {
                passKeyState.currentRegController.abort();
            } catch (e) {
                console.log('Error aborting previous controller:', e);
            }
        }
        passKeyState.currentRegController = controller;
    }
    
    // Create a timeout that will abort the fetch
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal,
            // Add cache control to prevent caching during network transitions
            headers: {
                ...options.headers,
                'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                'Pragma': 'no-cache'
            },
            // Use credentials to maintain session during network changes
            credentials: 'same-origin'
        });
        
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
}

function updateRegButtonState(isRegistering) {
    const regButton = document.querySelector('.register-button');
    if (regButton) {
        if (isRegistering) {
            regButton.disabled = true;
            regButton.textContent = 'Registering...';
        } else {
            regButton.disabled = false;
            regButton.textContent = 'Register New Passkey';
        }
    }
    
    // Also update the submit button in the modal
    const submitButton = document.querySelector('#registration-modal button:last-child');
    if (submitButton) {
        submitButton.disabled = isRegistering;
        submitButton.textContent = isRegistering ? 'Processing...' : 'Register';
    }
}
