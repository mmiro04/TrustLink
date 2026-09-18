const scanButton = document.getElementById("scanButton");
const urlInput = document.getElementById("urlInput");

const loading = document.getElementById("loading");
const result = document.getElementById("result");

const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");

const urlAnalysis = document.getElementById("urlAnalysis");
const dnsAnalysis = document.getElementById("dnsAnalysis");
const sslAnalysis = document.getElementById("sslAnalysis");
const redirectAnalysis = document.getElementById("redirectAnalysis");
const threatIntel = document.getElementById("threatIntel");

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
            "https://linktrust-api.onrender.com/scan",
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


/* ----------------------------- */
/* MAIN RESULT */
/* ----------------------------- */

function displayResult(data) {

    const risk = data.risk;

    riskLevel.textContent = risk.level;
    riskScore.textContent = risk.score;


    displayURLAnalysis(data.analysis);

    displayDNS(data.dns);

    displaySSL(data.ssl);

    displayRedirects(data.redirects);

    displayThreatIntel(data.threat_intel);

    displayReasons(risk.reasons);


    result.classList.remove("hidden");
}


/* ----------------------------- */
/* URL ANALYSIS */
/* ----------------------------- */

function displayURLAnalysis(data) {

    urlAnalysis.innerHTML = "";

    if (!data) {
        urlAnalysis.innerHTML = createItem(
            "STATUS",
            "No data available"
        );

        return;
    }

    urlAnalysis.innerHTML += createItem(
        "DOMAIN",
        data.domain || "N/A"
    );

    urlAnalysis.innerHTML += createItem(
        "HTTPS",
        data.https ? "Enabled" : "Disabled"
    );

    urlAnalysis.innerHTML += createItem(
        "IP ADDRESS",
        data.is_ip ? "Yes" : "No"
    );

    urlAnalysis.innerHTML += createItem(
        "PORT",
        data.port || (data.https ? "443" : "80")
    );

    urlAnalysis.innerHTML += createItem(
        "VALID",
        data.valid ? "Yes" : "No"
    );

    urlAnalysis.innerHTML += createItem(
        "SUSPICIOUS",
        data.suspicious ? "Detected" : "Not detected"
    );
}


/* ----------------------------- */
/* DNS */
/* ----------------------------- */

function displayDNS(data) {

    dnsAnalysis.innerHTML = "";

    if (!data) {

        dnsAnalysis.innerHTML = createItem(
            "STATUS",
            "Not available"
        );

        return;
    }

    dnsAnalysis.innerHTML += createItem(
        "A RECORDS",
        formatArray(data.a)
    );

    dnsAnalysis.innerHTML += createItem(
        "AAAA RECORDS",
        formatArray(data.aaaa)
    );

    dnsAnalysis.innerHTML += createItem(
        "CNAME",
        formatArray(data.cname)
    );

    dnsAnalysis.innerHTML += createItem(
        "MX RECORDS",
        formatArray(data.mx)
    );

    dnsAnalysis.innerHTML += createItem(
        "NS RECORDS",
        formatArray(data.ns)
    );

    if (data.errors && data.errors.length > 0) {

        dnsAnalysis.innerHTML += createItem(
            "ERROR",
            data.errors.join(" | ")
        );
    }
}


/* ----------------------------- */
/* SSL / TLS */
/* ----------------------------- */

function displaySSL(data) {

    sslAnalysis.innerHTML = "";

    if (!data) {

        sslAnalysis.innerHTML = createItem(
            "STATUS",
            "Not checked"
        );

        return;
    }

    sslAnalysis.innerHTML += createItem(
        "STATUS",
        data.valid ? "Valid TLS connection" : "Connection failed"
    );

    sslAnalysis.innerHTML += createItem(
        "TLS VERSION",
        data.tls_version || "N/A"
    );

    sslAnalysis.innerHTML += createItem(
        "ISSUER",
        formatCertificate(data.issuer)
    );

    sslAnalysis.innerHTML += createItem(
        "EXPIRES",
        data.expires || "N/A"
    );

    sslAnalysis.innerHTML += createItem(
        "DAYS UNTIL EXPIRY",
        data.days_until_expiry !== null
            ? data.days_until_expiry
            : "N/A"
    );

    if (data.error) {

        sslAnalysis.innerHTML += createItem(
            "ERROR",
            data.error
        );
    }
}


/* ----------------------------- */
/* REDIRECTS */
/* ----------------------------- */

function displayRedirects(data) {

    redirectAnalysis.innerHTML = "";

    if (!data) {

        redirectAnalysis.innerHTML = createItem(
            "STATUS",
            "Not checked"
        );

        return;
    }

    redirectAnalysis.innerHTML += createItem(
        "REDIRECT COUNT",
        data.redirect_count
    );

    redirectAnalysis.innerHTML += createItem(
        "FINAL URL",
        data.final_url || "N/A"
    );


    if (
        data.redirect_chain &&
        data.redirect_chain.length > 0
    ) {

        let chain = "";

        data.redirect_chain.forEach(
            (redirect, index) => {

                chain += `
                    <div class="redirect-item">
                        ${index + 1}. ${escapeHTML(
                            redirect.url
                        )}
                        →
                        ${escapeHTML(
                            redirect.location || "N/A"
                        )}
                        [${redirect.status_code}]
                    </div>
                `;
            }
        );

        redirectAnalysis.innerHTML += chain;

    } else {

        redirectAnalysis.innerHTML += createItem(
            "CHAIN",
            "No redirects detected"
        );
    }

    if (data.error) {

        redirectAnalysis.innerHTML += createItem(
            "ERROR",
            data.error
        );
    }
}


/* ----------------------------- */
/* THREAT INTELLIGENCE */
/* ----------------------------- */

function displayThreatIntel(data) {

    threatIntel.innerHTML = "";

    if (!data) {

        threatIntel.innerHTML = createItem(
            "STATUS",
            "Not available"
        );

        return;
    }

    threatIntel.innerHTML += createItem(
        "STATUS",
        data.available
            ? "Analysis completed"
            : (data.status || "Unavailable")
    );

    threatIntel.innerHTML += createItem(
        "MALICIOUS",
        data.malicious
    );

    threatIntel.innerHTML += createItem(
        "SUSPICIOUS",
        data.suspicious
    );

    threatIntel.innerHTML += createItem(
        "HARMLESS",
        data.harmless
    );

    threatIntel.innerHTML += createItem(
        "UNDETECTED",
        data.undetected
    );

    if (data.error) {

        threatIntel.innerHTML += createItem(
            "ERROR",
            data.error
        );
    }
}


/* ----------------------------- */
/* RISK REASONS */
/* ----------------------------- */

function displayReasons(reasonList) {

    reasons.innerHTML = "";

    if (!reasonList || reasonList.length === 0) {

        const li = document.createElement("li");

        li.textContent =
            "No suspicious indicators detected.";

        reasons.appendChild(li);

        return;
    }

    reasonList.forEach(reason => {

        const li = document.createElement("li");

        li.textContent = reason;

        reasons.appendChild(li);
    });
}


/* ----------------------------- */
/* HELPERS */
/* ----------------------------- */

function createItem(label, value) {

    return `
        <div class="data-item">

            <span class="data-label">
                ${escapeHTML(label)}
            </span>

            <span class="data-value">
                ${escapeHTML(String(value))}
            </span>

        </div>
    `;
}


function formatArray(array) {

    if (!array || array.length === 0) {
        return "None detected";
    }

    return array.join(", ");
}


function formatCertificate(certificate) {

    if (!certificate) {
        return "N/A";
    }

    if (typeof certificate === "string") {
        return certificate;
    }

    return JSON.stringify(certificate);
}


function escapeHTML(value) {

    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
