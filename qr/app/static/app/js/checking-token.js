//This function will request to check_token_status endpoint for every seconds to get True or False from this endpoint
//If the result is True it will log the user out
//if not True it will continue checking
function checkRedirectStatus() {
    fetch('/api/v1/check_token_status/', { method: 'GET' })
        .then(response => response.json())
        .then(data => {
            console.log("Redirect required:", data.redirect_required);
            if (data.redirect_required) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');

                window.location.href = "/";
            }
        })
        .catch(error => {
            console.error("Error checking redirect status:", error);
            window.location.href = "/";
        });
}

setInterval(checkRedirectStatus, 1000);


