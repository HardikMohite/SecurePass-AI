/**
 * error-handler.js — Global Error & Exception Wiring for SecurePass AI
 * Ensures that whenever an HTTP 403, 500, or critical network error throws,
 * the corresponding branded error page occurs immediately.
 * For 404 errors, ensures that NO error screen is displayed to the user,
 * seamlessly routing to the dashboard (/).
 */
(function () {
    'use strict';

    // Prevent recursive redirect loops if we are already on an error page
    const currentPath = window.location.pathname;
    const isErrorPage = currentPath.includes('403') || currentPath.includes('500') || currentPath.includes('404');

    /**
     * Store telemetry before navigating so error pages can display real-time diagnostics.
     */
    function recordError(status, message, endpoint) {
        try {
            sessionStorage.setItem('sp_last_error', JSON.stringify({
                status: status,
                message: message || (status === 403 ? 'Security Clearance Denied' : 'System Core Exception'),
                endpoint: endpoint || window.location.pathname,
                timestamp: new Date().toISOString()
            }));
        } catch (e) {
            // sessionStorage might be restricted in some environments
        }
    }

    /**
     * Programmatic API to trigger error pages from anywhere in the application.
     * @param {number} code - 403, 500, or 404
     * @param {string} [message] - Diagnostic details
     * @param {string} [endpoint] - Target URL or component
     */
    window.triggerError = function (code, message, endpoint) {
        recordError(code, message, endpoint);
        if (code === 403) {
            if (!currentPath.includes('403')) window.location.href = '/403';
        } else if (code === 500) {
            if (!currentPath.includes('500')) window.location.href = '/500';
        } else if (code === 404) {
            // Requirement: for 404 error do not show error to user
            if (currentPath !== '/' && !currentPath.endsWith('index.html')) {
                window.location.replace('/');
            }
        }
    };

    // If on an error page, don't intercept fetch to prevent interceptor feedback
    if (isErrorPage) {
        return;
    }

    // Intercept window.fetch globally across all scripts and components
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
        const resource = args[0];
        const url = typeof resource === 'string' ? resource : resource?.url || '';

        try {
            const response = await originalFetch.apply(this, args);

            // 1. Handle 403 Forbidden
            if (response.status === 403) {
                console.warn(`[SecurePass Sentinel] 403 Forbidden encountered at: ${url}`);
                recordError(403, 'Access Restricted: Elevated Clearance Required', url);
                window.location.href = '/403';
                return response;
            }

            // 2. Handle 500+ Internal Server / Cluster Errors
            if (response.status >= 500 && response.status <= 599) {
                console.error(`[SecurePass Sentinel] ${response.status} Server Error encountered at: ${url}`);
                recordError(response.status, `Server Exception (${response.statusText || 'Internal Server Error'})`, url);
                window.location.href = '/500';
                return response;
            }

            // 3. Handle 404 Not Found — per requirement: do NOT show error to user
            if (response.status === 404 && !url.startsWith('/api/')) {
                console.info(`[SecurePass Sentinel] 404 intercepted. Seamlessly routing to Dashboard.`);
                window.location.replace('/');
                return response;
            }

            return response;
        } catch (error) {
            // Network failure / Offline / Server crashed
            const isAborted = args[1]?.signal?.aborted;
            if (!isAborted && url.startsWith('/api/')) {
                console.error(`[SecurePass Sentinel] Fatal Network Failure connecting to ${url}:`, error);
                recordError(500, 'Network Disconnect: Inspection Cluster Unreachable', url);
                window.location.href = '/500';
            }
            throw error;
        }
    };

    // Listen for unhandled promise rejections with explicit error status
    window.addEventListener('unhandledrejection', function (event) {
        const reason = event.reason;
        if (reason && typeof reason === 'object') {
            if (reason.status === 403) {
                event.preventDefault();
                window.triggerError(403, reason.message || 'Access Forbidden');
            } else if (reason.status >= 500 && reason.status <= 599) {
                event.preventDefault();
                window.triggerError(reason.status, reason.message || 'Fatal Server Exception');
            }
        }
    });

})();
