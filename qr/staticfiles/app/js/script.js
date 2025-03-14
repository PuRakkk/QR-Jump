document.addEventListener("DOMContentLoaded", () => {
    setTimeout(() => {
        if (window.Telegram && window.Telegram.WebApp) {
            const telegram = window.Telegram.WebApp;

            if (telegram.initDataUnsafe && telegram.initDataUnsafe.user) {
                
                const user = telegram.initDataUnsafe.user;

                const { first_name, last_name, username, id } = user;

                console.log(`User Info: ${first_name} ${last_name} (@${username}), ID: ${id}`);

                document.getElementById("telegram_username").value = username;
                document.getElementById("telegram_id").value = id;

                if (!telegram_username || !telegram_id) {
                    alert("Failed to retrieve Telegram user information. Please refresh the page.");
                }

                const userInfoElementIndex = document.getElementById("user-info-index");
                

                if (userInfoElementIndex) {
                    userInfoElementIndex.innerText = `Welcome: ${first_name} ${last_name}`;
                }

                const userInfoElementUSDKHR = document.getElementById("user-info-transaction");
                if (userInfoElementUSDKHR) {
                    userInfoElementUSDKHR.innerText=  `User: ${first_name} ${last_name}`;
                }
                const userInfoCreatePin = document.getElementById("user-info-create-pin-page");
                if (userInfoCreatePin){
                    userInfoCreatePin.innerText = `Welcome:${first_name} ${last_name} to QR Jump`;
                }
                    
            } else {
                console.warn("User data is not available.");
            }
        } else {
            console.error("Telegram WebApp SDK is not available.");
        }
    },100);
});

function addNumber(num) {
    const pinInput = document.getElementById("pin");
    if (pinInput.value.length < 10) {
        pinInput.value += num;
    }
}

function clearNumber(){
    const pinInput = document.getElementById("pin");

    pinInput.value = "";
}

function addNumberUSD_tx(num) {
    const pinInputUSD = document.getElementById("usd-amount");

    if (num === '.' && (pinInputUSD.value.includes('.') || pinInputUSD.value === '')) {
        return; 
    }

    const parts = pinInputUSD.value.split('.');
    if (parts.length === 2 && parts[1].length >= 2 && num !== '.') {
        return;
    }

    if (pinInputUSD.value.length < 9) {
        pinInputUSD.value += num;
    }
    validateUSDInput();
}

function clearNumberUSD_tx(){
    const pinInputUSD = document.getElementById("usd-amount");

    pinInputUSD.value = "";
}

function addNumberKHR_tx(num) {
    const pinInputKHR = document.getElementById("khr-amount");

    if (num === '.' || isNaN(num)) {
        return;
    }

    const currentValue = pinInputKHR.value;
    const remainLength = 9 - currentValue.length;
    if (remainLength > 0) {
        pinInputKHR.value += num.toString().slice(0, remainLength);
    }
}

function clearNumberKHR_tx() {
    const pinInputKHR = document.getElementById("khr-amount");
    pinInputKHR.value = "";

}

function addCreatePinNumber(num) {
    const pinInput = document.getElementById("create-pin");
    if (pinInput.value.length < 8) {
        pinInput.value += num;
    }
}

function clearCreatePinNumber(){
    const pinInput = document.getElementById("create-pin");
    pinInput.value = "";
}

function goToKhrTransaction() {
    window.location.href = '/khr-transaction';
}

function goToUsdTransaction() {
    window.location.href = '/change-usd-transaction';
}

function goToConfirmPage(currency) {
    // Get the input amount and convert it to a number
    const amountInput = currency === 'USD' 
        ? document.getElementById('usd-amount').value 
        : document.getElementById('khr-amount').value;

    // Remove spaces and format the amount
    const amountWithoutSpaces = amountInput.replace(/\s/g, '');

    const amount = parseFloat(amountWithoutSpaces);

    if (currency === 'USD') {
        if (!isNaN(amount) && amount >= 0.01) {
            // Format the amount to 2 decimal places for USD
            const formattedAmount = amount.toFixed(2);
            const confirmUrl = `/confirm-transaction/?currency=${currency}&amount=${formattedAmount}`;
            window.location.href = confirmUrl;
        } else {
            alert('Amount must start from 0.01 USD');
            clearNumberUSD_tx();
        }
    } else if (currency === 'KHR') {
        if (!isNaN(amount) && amount >= 100) {
            const formattedAmount = formatWithSpaces(amount); // This is still for display purposes
            const confirmUrl = `/confirm-transaction/?currency=${currency}&amount=${formattedAmount}`;
            window.location.href = confirmUrl;
        } else {
            alert('Amount must start from 100 Riels');
            clearNumberKHR_tx();
        }
    }
}

function formatWithSpaces(value) {
    return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
}

function removeSpaces(value) {
    return value.replace(/\s+/g, '');  // Removes all spaces
}

function updateDateTime() {
    const now = new Date();
    
    // Get formatted date parts
    const options = { month: 'short', day: '2-digit', year: 'numeric' };
    const formattedDate = now.toLocaleDateString('en-US', options);
    
    // Get hours, minutes, and AM/PM format
    let hours = now.getHours();
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    
    // Convert to 12-hour format
    hours = hours % 12 || 12;
    
    // Combine all parts
    const formattedDateTime = `${formattedDate} ${hours}:${minutes} ${ampm}`;

    

    document.getElementById("datetime-index").innerText = formattedDateTime;

}

setInterval(updateDateTime, 1000);

updateDateTime();

function goBackToTransactionPageFromConfirmPage() {
    const currencyType = document.querySelector('.cancel-btn').getAttribute('data-currency');

    if (currencyType === 'USD') {
        window.location.href = '/change-usd-transaction';
    } else if (currencyType === 'KHR') {
        window.location.href = '/khr-transaction';
    }
}

function disableBackButton() {
    console.log("Back button disable function activated");
    window.history.pushState(null, "", window.location.href);
    window.onpopstate = function () {
        window.history.pushState(null, "", window.location.href);
    };
}

function redirectToQRPage(method, amount, currency) {
    console.log("Redirect function called for:", method, amount, currency);

    // Get the telegram_id and telegram_username from Telegram Web App
    const telegramId = Telegram.WebApp.initDataUnsafe?.user?.id;  // Get user ID from Telegram
    const telegramUsername = Telegram.WebApp.initDataUnsafe?.user?.username; // Get username from Telegram

    if (!telegramId || !telegramUsername) {
        alert("Telegram ID or Username is missing.");
        return; // Stop if Telegram ID or username is missing
    }

    withoutspaceAmount = removeSpaces(amount);

    if (withoutspaceAmount && currency) {
        // Create a form dynamically
        const form = document.createElement("form");
        form.method = "POST";  // POST method
        form.action = `/qr-generate/${method}/${withoutspaceAmount}/${currency}/`;  // Set your URL for QR generation

        // Add the CSRF token as a hidden input
        const csrfTokenInput = document.createElement("input");
        csrfTokenInput.type = "hidden";
        csrfTokenInput.name = "csrfmiddlewaretoken";
        csrfTokenInput.value = document.querySelector('[name="csrfmiddlewaretoken"]').value; // Get the CSRF token from the page

        // Create hidden inputs for telegram_id and telegram_username
        const telegramIdInput = document.createElement("input");
        telegramIdInput.type = "hidden";
        telegramIdInput.name = "telegram_id";
        telegramIdInput.value = telegramId;  // Set telegram ID

        const telegramUsernameInput = document.createElement("input");
        telegramUsernameInput.type = "hidden";
        telegramUsernameInput.name = "telegram_username";
        telegramUsernameInput.value = telegramUsername;  // Set telegram username

        // Append the hidden inputs to the form
        form.appendChild(csrfTokenInput);
        form.appendChild(telegramIdInput);
        form.appendChild(telegramUsernameInput);

        // Append form to body and submit
        document.body.appendChild(form);
        form.submit();  // Submit the form via POST request

    } else {
        alert("Please enter both amount and currency.");
    }
}
function goBackToTransactionPageFromQRGenerate() {
    const currencyType = document.querySelector('.qr-close-btn').getAttribute('data-currency');

    if (currencyType === 'USD') {
        window.location.href = '/change-usd-transaction';
    } else if (currencyType === 'KHR') {
        window.location.href = '/khr-transaction';
    }
}

function redirectToHistory() {
    const telegramId = document.getElementById("telegram_id").value;

    if (telegramId) {
        window.location.href = `/transaction-history/?telegram_id=${telegramId}`;
    } else {
        alert("Telegram ID is missing. Unable to fetch history.");
    }
}

function goBackToTransactionPageFromHistoryPage(currency) {

    if (currency === 'USD') {
        window.location.href = '/change-usd-transaction';
    } else if (currency === 'KHR') {
        window.location.href = '/khr-transaction';
    }
}

function goBackToTransactionPageFromHistoryPageIfNoTran() {

        window.location.href = '/change-usd-transaction';
}

