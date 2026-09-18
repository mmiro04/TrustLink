const scanButton = document.getElementById("scanButton");
const urlInput = document.getElementById("urlInput");

const loading = document.getElementById("loading");
const result = document.getElementById("result");

const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");
const reasons = document.getElementById("reasons");


scanButton.addEventListener("click", scanURL);


async function scanURL() {

    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    loading.classList.remove("hidden");
    result.classList.add("hidden");

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );

        if (!response.ok) {
            throw new Error(
                `Server returned HTTP ${response.status}`
            );
        }

        const data = await response.json();

        displayResult(data);

    } catch (error) {

        console.error(error);

        alert(
            "Unable to connect to the LinkTrust API."
        );

    } finally {

        loading.classList.add("hidden");
    }
}


function displayResult(data) {

    const risk = data.risk;

    riskLevel.textContent = risk.level;
    riskScore.textContent = risk.score;

    reasons.innerHTML = "";

    if (risk.reasons.length === 0) {

        const li = document.createElement("li");

        li.textContent = "No suspicious indicators detected.";

        reasons.appendChild(li);

    } else {

        risk.reasons.forEach(reason => {

            const li = document.createElement("li");

            li.textContent = reason;

            reasons.appendChild(li);

        });
    }

    result.classList.remove("hidden");
}
