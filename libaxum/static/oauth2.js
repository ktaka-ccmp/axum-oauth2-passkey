function initOAuth2Popup() {
    let popupWindow;
    let isReloading = false;

    function openPopup() {
        popupWindow = window.open(
            `${AUTH_ROUTE_PREFIX}/google`,
            "PopupWindow",
            "width=400,height=520,left=1000,top=200,resizable=yes,scrollbars=yes"
        );

        // Listen for messages from the auth popup
        window.addEventListener('message', function(event) {
            // Make sure to verify the origin matches your domain
            if (event.data === 'auth_complete') {
                handlePopupClosed();
            }
        });
    }

    function handlePopupClosed() {
        if (isReloading) return;  // Prevent multiple reloads
        isReloading = true;

        const statusElement = document.getElementById('status');
        if (statusElement) {
            statusElement.textContent = 'Popup closed. Reloading parent...';
        }

        // Reload the parent window
        setTimeout(() => {
            window.location.reload();
        }, 100);  // Wait for 0.1 second before reloading
    }

    // Clean up on page unload
    window.addEventListener('unload', () => {
        if (popupWindow) {
            try {
                if (!popupWindow.closed) {
                    // popupWindow.close();
                }
            } catch (e) {
                // Handle COOP error silently
            }
        }
    });

    return {
        openPopup: openPopup
    };
}
