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
                const userInfoBranch = document.getElementById("user-info-branch");
                if (userInfoBranch){
                    userInfoBranch.innerText = `User: ${first_name} ${last_name}`;
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

function goToKhrTransaction(telegramUsername, staffUserPin) {
    const url = `/khr-transaction?telegram_username=${encodeURIComponent(telegramUsername)}&staff_user_pin=${encodeURIComponent(staffUserPin)}`;
    window.location.href = url;
}

function goToUsdTransaction(telegramUsername, staffUserPin) {
    const url = `/usd-transaction?telegram_username=${encodeURIComponent(telegramUsername)}&staff_user_pin=${encodeURIComponent(staffUserPin)}`;
    window.location.href = url;
}

function logout() {
    fetch('/logout-user', {
        method: 'GET',
    })
    .then(response => {
        if (response.ok) {
            window.location.href = '/';
        }
    })
    .catch(error => {
        console.error('Error logging out:', error);
    });
}
function goToConfirmPage(currency) {
    const amountInput = currency === 'USD' 
        ? document.getElementById('usd-amount').value 
        : document.getElementById('khr-amount').value;

    const amountWithoutSpaces = amountInput.replace(/\s/g, '');

    const amount = parseFloat(amountWithoutSpaces);

    if (currency === 'USD') {
        if (!isNaN(amount) && amount >= 0.01) {
            const formattedAmount = amount.toFixed(2);
            const confirmUrl = `/confirm-transaction/?currency=${currency}&amount=${formattedAmount}`;
            window.location.href = confirmUrl;
        } else {
            alert('Amount must start from 0.01 USD');
            clearNumberUSD_tx();
        }
    } else if (currency === 'KHR') {
        if (!isNaN(amount) && amount >= 100) {
            const formattedAmount = formatWithSpaces(amount); 
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
    return value.replace(/\s+/g, ''); 
}

function updateDateTime() {
    const now = new Date();
    
    const options = { month: 'short', day: '2-digit', year: 'numeric' };
    const formattedDate = now.toLocaleDateString('en-US', options);
    
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    
    const formattedDateTime = `${formattedDate} ${hours}:${minutes}`;

    document.getElementById("datetime-index").innerText = formattedDateTime;
}

setInterval(updateDateTime, 1000);

updateDateTime();

function goBackToTransactionPageFromConfirmPage() {
    const currencyType = document.querySelector('.cancel-btn').getAttribute('data-currency');

    if (currencyType === 'USD') {
        window.location.href = '/usd-transaction';
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

    const telegramId = Telegram.WebApp.initDataUnsafe?.user?.id;
    const telegramUsername = Telegram.WebApp.initDataUnsafe?.user?.username;

    if (!telegramId || !telegramUsername) {
        alert("Telegram ID or Username is missing.");
        return;
    }

    withoutspaceAmount = removeSpaces(amount);

    if (withoutspaceAmount && currency) {
        const form = document.createElement("form");
        form.method = "POST";
        form.action = `/aba-qr-generate/${method}/${withoutspaceAmount}/${currency}/`; 

        const csrfTokenInput = document.createElement("input");
        csrfTokenInput.type = "hidden";
        csrfTokenInput.name = "csrfmiddlewaretoken";
        csrfTokenInput.value = document.querySelector('[name="csrfmiddlewaretoken"]').value;

        const telegramIdInput = document.createElement("input");
        telegramIdInput.type = "hidden";
        telegramIdInput.name = "telegram_id";
        telegramIdInput.value = telegramId; 

        const telegramUsernameInput = document.createElement("input");
        telegramUsernameInput.type = "hidden";
        telegramUsernameInput.name = "telegram_username";
        telegramUsernameInput.value = telegramUsername;

        form.appendChild(csrfTokenInput);
        form.appendChild(telegramIdInput);
        form.appendChild(telegramUsernameInput);

        document.body.appendChild(form);
        form.submit(); 

    } else {
        alert("Please enter both amount and currency.");
    }
}
function goBackToTransactionPageFromQRGenerate() {
    const currencyType = document.querySelector('.qr-close-btn').getAttribute('data-currency');

    if (currencyType === 'USD') {
        window.location.href = '/usd-transaction';
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

    if (currency === 'USD' || currency === 'usd') {
        window.location.href = '/usd-transaction';
    } else if (currency === 'KHR' || currency === 'khr') {
        window.location.href = '/khr-transaction';
    }
}

function goBackToTransactionPageFromHistoryPageIfNoTran() {

        window.location.href = '/usd-transaction';
}

function goBackToTransactionPageFromQrPage(currency) {
    sessionStorage.removeItem("loading_done");
    sessionStorage.removeItem("checkout_done");
    if (currency === 'USD' || currency === 'usd') {
        window.location.href = '/usd-transaction';
    } else if (currency === 'KHR' || currency === 'khr') {
        window.location.href = '/khr-transaction';
    }
}

