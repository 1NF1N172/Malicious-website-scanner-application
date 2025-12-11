function submitFeedback(type) {
    fetch(`/feedback?link={{ link }}&type=${type}`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                document.getElementById('feedback-message').innerText = data.error;
            } else {
                if (data.bad_response_count >= 3) {
                    document.getElementById('prediction').innerText = 'Legitimate';
                    document.getElementById('prediction').className = 'prediction-legitimate';
                }
                
                document.getElementById('feedback-message').innerText = 'Thank you for your feedback!';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('feedback-message').innerText = 'An error occurred. Please try again.';
        });
}

function redirectToSearchPage() {
    window.location.href = "/";  // Redirects to the homepage
}

function copyToClipboard() {
    const resultText = `
        URL: ${document.getElementById('result-url').href}
        Prediction: ${document.getElementById('prediction').innerText}
        IP Address: ${document.getElementById('result-ip').innerText}
        Country: ${document.getElementById('result-country').innerText}
        Region: ${document.getElementById('result-region').innerText}
        City: ${document.getElementById('result-city').innerText}
        Latitude: ${document.getElementById('result-latitude').innerText}
        Longitude: ${document.getElementById('result-longitude').innerText}
        Zip Code: ${document.getElementById('result-zip').innerText}
        Time Zone: ${document.getElementById('result-timezone').innerText}
    `;

    navigator.clipboard.writeText(resultText.trim())
        .then(() => {
            document.getElementById('feedback-message').innerText = 'Result copied to clipboard!';
        })
        .catch(err => {
            document.getElementById('feedback-message').innerText = 'Failed to copy result. Please try again.';
            console.error('Could not copy text: ', err);
        });
}

function initMap(lat, lon) {
    if (!lat || !lon || isNaN(lat) || isNaN(lon)) {
        console.error("Invalid latitude or longitude values.");
        return;
    }

    const map = L.map('map').setView([lat, lon], 13);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    L.marker([lat, lon]).addTo(map)
        .bindPopup('Location: ' + lat + ', ' + lon)
        .openPopup();
}

document.addEventListener('DOMContentLoaded', function() {
    const lat = parseFloat('{{ location_info.latitude if location_info else "NaN" }}');
    const lon = parseFloat('{{ location_info.longitude if location_info else "NaN" }}');

    initMap(lat, lon);
});
