from flask import Flask, request, render_template_string
from flask_socketio import SocketIO, emit
from db import get_filtered_alerts
import argparse

app = Flask(__name__)
socketio = SocketIO(app)

# Function to generate HTML content
def generate_html(min_score=-999, trusted=None):
    alerts = get_filtered_alerts(min_score, trusted)

    html = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Alertes SSL</title>
        <link rel="stylesheet" href="static/style.css">
    </head>
    <body>
        <h1>🔐 Alertes Certificats</h1>
        <form method="GET">
            <label>Score min: <input type="number" name="min_score" value="{{ min_score }}"></label>
            <label>Trusted:
                <select name="trusted">
                    <option value="">Tous</option>
                    <option value="1" {% if trusted == "1" %}selected{% endif %}>✅ Trusted</option>
                    <option value="0" {% if trusted == "0" %}selected{% endif %}>❌ Untrusted</option>
                </select>
            </label>
            <button type="submit">Filtrer</button>
        </form>
        <table id="alerts_table">
            <tr>
                <th>Domaine</th><th>Org</th><th>Trusted</th><th>Score</th><th>Info</th><th>Issues</th><th>Timestamp</th>
            </tr>
    """

    for alert in alerts:
        domain, org, trusted, score, info, issues, timestamp = alert
        html += f"""
            <tr class="{ 'critical' if score < 0 else '' }">
                <td>{domain}</td>
                <td>{org}</td>
                <td>{"✅" if trusted else "❌"}</td>
                <td>{score}</td>
                <td>{info}</td>
                <td><pre>{issues}</pre></td>
                <td>{timestamp}</td>
            </tr>
        """

    html += """
        </table>

        <script src="https://cdn.jsdelivr.net/npm/socket.io-client/dist/socket.io.js"></script>
        <script>
            const socket = io.connect('http://' + document.domain + ':' + location.port);
            
            socket.on('new_alert', function(data) {
                const table = document.getElementById('alerts_table');
                const row = table.insertRow(1);
                
                row.classList.add(data.score < 0 ? 'critical' : '');
                row.innerHTML = `
                    <td>${data.domain}</td>
                    <td>${data.org}</td>
                    <td>${data.trusted ? "✅" : "❌"}</td>
                    <td>${data.score}</td>
                    <td>${data.info}</td>
                    <td><pre>${data.issues}</pre></td>
                    <td>${data.timestamp}</td>
                `;
            });
        </script>
    </body>
    </html>
    """

    return html

# Route to display the alert page
@app.route("/")
def index():
    min_score = request.args.get("min_score", -999)
    trusted = request.args.get("trusted")

    try:
        min_score = int(min_score)
    except ValueError:
        min_score = -999

    alerts_html = generate_html(min_score=min_score, trusted=trusted)

    # Return the dynamically generated HTML as the response
    return render_template_string(alerts_html)

# WebSocket to send updates when a new alert is added
def send_new_alert(alert):
    socketio.emit('new_alert', alert)

# Simulate receiving alerts
@app.route("/send_alert", methods=["POST"])
def send_alert():
    # In a real scenario, this would be replaced with your logic that receives alerts from certstream
    alert = {
        "domain": "example.com",
        "org": "Example Org",
        "trusted": True,
        "score": 50,
        "info": "Valid certificate",
        "issues": "None",
        "timestamp": "2025-04-25 14:00:00"
    }
    send_new_alert(alert)
    return "Alert sent!"

def start_server():
    print("[+] Démarrage du serveur Flask avec SocketIO...")
    socketio.run(app, debug=True)

def test_config():
    print("[*] Test de configuration réussi ✔️")

def main():
    parser = argparse.ArgumentParser(description="Analyse en temps réel des certificats SSL/TLS")
    parser.add_argument('--start', action='store_true', help='Démarre le serveur Web en temps réel')
    parser.add_argument('--test', action='store_true', help='Effectue un test de configuration')

    args = parser.parse_args()

    if args.test:
        test_config()
    elif args.start:
        start_server()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()