// Function to detect phishing and display result
function detectPhishing() {
    var domain = document.getElementById('domainInput').value;
    fetch('/predict', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domain: domain })
    })
        .then(response => response.json())
        .then(data => {
            document.getElementById('result').innerText = 'Result: ' + data.result;
        })
        .catch(error => console.error('Error:', error));
}

// Function to navigate to a different page
function goToPage(page) {
    window.location.href = page;
}
