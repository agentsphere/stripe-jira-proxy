import os
import requests
from google.cloud import firestore

import json
import uuid # Only if generating UUIDs *here*, usually Forge generates them
from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY') # Needed if making API calls *from* here, not needed just for webhooks
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
PROXY_TO_FORGE_SECRET = os.getenv('PROXY_TO_FORGE_SECRET')
REGISTER_API_KEY = os.getenv('REGISTER_API_KEY') # Secret to protect registration

# Basic input validation
if not STRIPE_WEBHOOK_SECRET:
    print("Error: STRIPE_WEBHOOK_SECRET environment variable not set.")
    exit(1)
if not PROXY_TO_FORGE_SECRET:
    print("Error: PROXY_TO_FORGE_SECRET environment variable not set.")
    exit(1)
# if not REGISTER_API_KEY: # Optional: uncomment if you want to enforce registration key
#     print("Warning: REGISTER_API_KEY environment variable not set. Registration endpoint is less secure.")
try:
    db = firestore.Client()
    FIRESTORE_COLLECTION = "forge_installation_mappings" # Define collection name
    print(f"Firestore client initialized. Using collection: {FIRESTORE_COLLECTION}")
except Exception as e:
    print(f"Error initializing Firestore client: {e}")
    print("Ensure Application Default Credentials (ADC) are configured correctly.")
    exit(1)

# Configure Stripe client (only needed if making API calls)
# stripe.api_key = STRIPE_SECRET_KEY

# --- In-Memory Storage (NOT SUITABLE FOR PRODUCTION!) ---
# Replace this with a persistent database (Redis, PostgreSQL, DynamoDB, Firestore etc.) in production
installation_map = {}
print(f"Initial empty installation map: {installation_map}")

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Endpoints ---

@app.route('/register', methods=['POST'])
def register_forge_installation():
    """
    Endpoint for Forge app instances to register their UUID and Web Trigger URL.
    Forge app should call this during its installation lifecycle handler.
    """
    # Optional: Basic security check for the registration endpoint
    provided_reg_key = request.headers.get('X-Registration-Api-Key')
    if REGISTER_API_KEY and provided_reg_key != REGISTER_API_KEY:
         print(f"Registration attempt failed: Invalid API Key '{provided_reg_key}'")
         abort(401, description="Unauthorized: Invalid registration API Key.")

    # --- Get Data ---
    data = request.json
    if not data:
        abort(400, description="Invalid request: Missing JSON body.")

    installation_uuid = data.get('installation_uuid')
    forge_webtrigger_url = data.get('forge_webtrigger_url')

    if not installation_uuid or not forge_webtrigger_url:
        abort(400, description="Invalid request: Missing 'installation_uuid' or 'forge_webtrigger_url'.")
    try:
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(installation_uuid)
        doc_ref.set({
            "installation_uuid": installation_uuid,
            "forge_webtrigger_url": forge_webtrigger_url,
        })
        print(f"Stored/Updated mapping in Firestore for UUID={installation_uuid}, URL={forge_webtrigger_url}")
    except Exception as e:
        print(f"Error writing to Firestore for UUID {installation_uuid}: {e}")
        abort(500, description="Failed to store registration data.")

    # --- Store Mapping ---
    # !! WARNING: In-memory storage lost on restart !!
    installation_map[installation_uuid] = forge_webtrigger_url
    print(f"Registered/Updated installation: UUID={installation_uuid}, URL={forge_webtrigger_url}")
    print(f"Current installation map: {installation_map}")

    return jsonify({"status": "registered", "installation_uuid": installation_uuid}), 200


@app.route('/stripe-webhook', methods=['POST'])
def handle_stripe_webhook():
    """
    Receives webhook events from Stripe, verifies signature, looks up
    Forge URL from Firestore based on metadata, and forwards the event.
    """
    payload = request.data # Raw body

    print(payload)

    data_json= json.loads(payload)
    # 2. Extract Metadata and Installation UUID (same as before)
    metadata = data_json.get('metadata', {})
    installation_uuid = metadata.get('installation_uuid') # Key must match what Forge sends

    if not installation_uuid:
        print("Event missing 'installation_uuid' in metadata. Cannot forward.")
        return jsonify({"status": "received_missing_metadata"}), 200

    print(f"Event {installation_uuid} received for installation UUID: {installation_uuid}")

    # 3. Lookup Forge URL from Firestore
    forge_url = None
    try:
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(installation_uuid)
        doc = doc_ref.get()

        if doc.exists:
            doc_data = doc.to_dict()
            forge_url = doc_data.get("forge_webtrigger_url")
            if forge_url:
                 print(f"Found Forge URL in Firestore: {forge_url} for UUID: {installation_uuid}")
            else:
                 print(f"Warning: Document found for UUID {installation_uuid} but 'forge_webtrigger_url' field is missing.")
        else:
            print(f"Error: Installation UUID {installation_uuid} not found in Firestore collection '{FIRESTORE_COLLECTION}'. Cannot forward.")
            # Still return 200 to Stripe, but log the problem.
            return jsonify({"status": "received_installation_not_found"}), 200

    except Exception as e:
        print(f"Error reading from Firestore for UUID {installation_uuid}: {e}")
        # Still return 200 to Stripe, but log the problem.
        return jsonify({"status": "received_firestore_read_error"}), 200

    # Check if we actually got a URL
    if not forge_url:
         print(f"Error: Could not retrieve valid Forge URL for UUID {installation_uuid}. Cannot forward.")
         return jsonify({"status": "received_invalid_forge_url_data"}), 200


    # 4. Forward Request to Forge Web Trigger (same as before)
    headers = {
        'Content-Type': 'application/json',
        'X-AgentSphere-Proxy-Secret': PROXY_TO_FORGE_SECRET
    }
    try:
        print(f"Forwarding event to {forge_url}...")
        response = requests.post(forge_url, headers=headers, data=payload, timeout=10)
        response.raise_for_status()
        print(f"Successfully forwarded event Forge response status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error forwarding event to {forge_url}: {e}")
        # Log error, but still return 200 below

    # 5. Return Success to Stripe (same as before)
    return jsonify({"status": "received_forwarded"}), 200




@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "healthy"}), 200

# --- Run the App ---
if __name__ == '__main__':
    # Use PORT environment variable if available (for deployment platforms)
    port = int(os.environ.get('PORT', 5000))
    # Set debug=False for production
    app.run(host='0.0.0.0', port=port, debug=True)