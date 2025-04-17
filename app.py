import os
import requests
from google.cloud import firestore
import json
import uuid # Only if generating UUIDs *here*, usually Forge generates them
from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv
import logging # Import the logging library
import sys # Needed for StreamHandler output
import stripe

# --- Load Environment Variables ---
load_dotenv()


# --- Logging Configuration ---
# Configure logging BEFORE anything else tries to log
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(process)d - [%(filename)s:%(lineno)d] - %(message)s'
logging.basicConfig(
    level=logging.INFO, # Set the default log level (e.g., INFO, DEBUG, WARNING)
    format=log_format,
    handlers=[
        logging.StreamHandler(sys.stdout) # Log to standard output (captured by Cloud Run Logging)
    ]
)
# Get a logger instance for this module
logger = logging.getLogger(__name__)
logger.info("This is version 0.0.1")

# --- Configuration ---
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY') # Needed if making API calls *from* here, not needed just for webhooks
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
PROXY_TO_FORGE_SECRET = os.getenv('PROXY_TO_FORGE_SECRET')
REGISTER_API_KEY = os.getenv('REGISTER_API_KEY') # Secret to protect registration

# Basic input validation with logging
if not STRIPE_WEBHOOK_SECRET:
    logger.critical("CRITICAL: STRIPE_WEBHOOK_SECRET environment variable not set. Exiting.")
    exit(1)
else:
    logger.info("STRIPE_WEBHOOK_SECRET found.")
stripe.api_key = STRIPE_SECRET_KEY # Set if not already done globally
if not PROXY_TO_FORGE_SECRET:
    logger.critical("CRITICAL: PROXY_TO_FORGE_SECRET environment variable not set. Exiting.")
    exit(1)
else:
    logger.info("PROXY_TO_FORGE_SECRET found.")

if not REGISTER_API_KEY: # Optional: uncomment if you want to enforce registration key
    logger.warning("Warning: REGISTER_API_KEY environment variable not set. Registration endpoint is less secure.")
else:
    logger.info("REGISTER_API_KEY found.")

# --- Firestore Initialization ---
FIRESTORE_COLLECTION = "forge_installation_mappings" # Define collection name
db = None # Initialize db to None
try:
    db = firestore.Client(
        project="psyched-option-454007-u6", database="test"
    )
    # db = firestore.Client() # Use this if relying solely on ADC in Cloud Run
    logger.info(
        "Firestore client initialized successfully for project 'psyched-option-454007-u6', database 'test'. Using collection: %s",
        FIRESTORE_COLLECTION
    )
except Exception as e:
    # Use lazy formatting for the error message argument
    logger.critical("CRITICAL: Error initializing Firestore client: %s", e, exc_info=True) # exc_info=True adds traceback
    logger.critical("Ensure Application Default Credentials (ADC) are configured correctly or service account key is valid.")
    exit(1) # Exit if DB connection fails on startup

# Configure Stripe client (only needed if making API calls)
# import stripe
# stripe.api_key = STRIPE_SECRET_KEY
# logger.info("Stripe API key configured (if needed).")


# --- Flask App Initialization ---
app = Flask(__name__)
logger.info("Flask app initialized.")

# --- Endpoints ---

@app.route('/register', methods=['POST'])
def register_forge_installation():
    """
    Endpoint for Forge app instances to register their UUID and Web Trigger URL.
    Forge app should call this during its installation lifecycle handler.
    """
    logger.info("'/register' endpoint called.")
    # Optional: Basic security check for the registration endpoint
    provided_reg_key = request.headers.get('X-Registration-Api-Key')
    if REGISTER_API_KEY and provided_reg_key != REGISTER_API_KEY:
        # Evaluate complex expression outside the logger call for clarity with lazy formatting
        reg_key_prefix = provided_reg_key[:4] if provided_reg_key else 'None'
        logger.warning("Registration attempt failed: Invalid API Key provided. Key starts with: '%s...'", reg_key_prefix) # Avoid logging full key
        abort(401, description="Unauthorized: Invalid registration API Key.")

    # --- Get Data ---
    data = request.json
    if not data:
        logger.error("Registration failed: Invalid request - Missing JSON body.")
        abort(400, description="Invalid request: Missing JSON body.")

    installation_uuid = data.get('installation_uuid')
    forge_webtrigger_url = data.get('forge_webtrigger_url')

    if not installation_uuid or not forge_webtrigger_url:
        logger.error("Registration failed: Invalid request - Missing 'installation_uuid' or 'forge_webtrigger_url'.")
        abort(400, description="Invalid request: Missing 'installation_uuid' or 'forge_webtrigger_url'.")

    # Use lazy formatting
    logger.info("Attempting to register/update installation UUID: %s", installation_uuid)
    # Avoid logging the full URL unless necessary for debugging
    # logger.debug("Received forge_webtrigger_url: %s", forge_webtrigger_url)

    try:
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(installation_uuid)
        doc_ref.set({
            "installation_uuid": installation_uuid,
            "forge_webtrigger_url": forge_webtrigger_url,
            # Consider adding a timestamp:
            # "last_registered_at": firestore.SERVER_TIMESTAMP
        })
        # Use lazy formatting
        logger.info("Successfully stored/updated mapping in Firestore for UUID=%s", installation_uuid)
    except Exception as e:
        # Use lazy formatting, passing variables as arguments
        logger.error("Error writing to Firestore for UUID %s: %s", installation_uuid, e, exc_info=True)
        abort(500, description="Failed to store registration data.")

    # Use lazy formatting
    logger.info("Successfully registered/updated installation: UUID=%s", installation_uuid)

    return jsonify({"status": "registered", "installation_uuid": installation_uuid}), 200



@app.route('/stripe-webhook', methods=['POST'])
async def handle_stripe_webhook():
    """
    Receives webhook events from Stripe, verifies signature, looks up
    Forge URL from Firestore based on metadata, and forwards the event.
    """
    logger.info("'/stripe-webhook' endpoint called.")
    payload = request.data # Raw body


    logger.info("Received webhook payload (length: %d bytes).", len(payload))
    logger.debug("Webhook payload: %s", payload) # Be cautious with logging sensitive data
    event= None
    try:
        # Debug log the actual payload if necessary, but be wary of size/sensitivity
        json_object = json.loads(payload)
        logger.debug("Parsed JSON object: %s", json_object) # Be cautious with sensitive data
        event_id=json_object.get("id", None)
        if event_id is None:
            logger.error("Error: Event ID not found in payload.")
            return jsonify(status='invalid payload'), 400
        event = await stripe.events.retrieve(event_id);
        if event is None:
            logger.error("Error: Event not found in Stripe.")
            return jsonify(status='event_not_found'), 400
    except Exception as e:
        # Invalid payload
        # Use lazy formatting
        logger.error("Error: %s", e)
        return jsonify(status='invalid payload'), 400

    pi_obj = stripe.PaymentIntent.retrieve(event.data.object.payment_intent) # Example of using the event dat
    logger.info("PaymentIntent object retrieved: %s", pi_obj)
    metadata = pi_obj.get('metadata', {})

    installation_uuid = metadata.get('installation_uuid') # Key must match what Forge sends

    if not installation_uuid:
        # Use lazy formatting
        logger.warning("Webhook event (installation_uuid: %s) missing 'installation_uuid' in data.object.metadata. Cannot forward.",
                       installation_uuid)
        # Return 200 OK to Stripe so it doesn't retry, but log the issue.
        return jsonify({"status": "received_missing_metadata"}), 200

    # Use lazy formatting
    logger.info("Webhook event (installation_uuid: %s) received for installation UUID: %s",
                installation_uuid, installation_uuid)

    # 3. Lookup Forge URL from Firestore
    forge_url = None
    try:
        doc_ref = db.collection(FIRESTORE_COLLECTION).document(installation_uuid)
        doc = doc_ref.get()

        if doc.exists:
            doc_data = doc.to_dict()
            forge_url = doc_data.get("forge_webtrigger_url")
            if forge_url:
                # Use lazy formatting
                logger.info("Found Forge URL in Firestore for UUID: %s", installation_uuid)
                # Avoid logging the URL itself: logger.debug("Forge URL: %s", forge_url)
            else:
                # Use lazy formatting
                logger.warning("Document found for UUID %s but 'forge_webtrigger_url' field is missing or empty.", installation_uuid)
                # Still return 200 to Stripe
                return jsonify({"status": "received_installation_found_no_url"}), 200
        else:
            # Use lazy formatting
            logger.error("Installation UUID %s not found in Firestore collection '%s'. Cannot forward webhook event.",
                         installation_uuid, FIRESTORE_COLLECTION)
            # Still return 200 to Stripe
            return jsonify({"status": "received_installation_not_found"}), 200

    except Exception as e:
        # Use lazy formatting
        logger.error("Error reading from Firestore for UUID %s : %s",
                     installation_uuid, e, exc_info=True)
        # Still return 200 to Stripe
        return jsonify({"status": "received_firestore_read_error"}), 200

    # Check if we actually got a URL (handles the case where the field exists but is null/empty)
    if not forge_url:
        # Use lazy formatting
        logger.error("Could not retrieve a valid Forge URL for UUID %s. Cannot forward.",
                      installation_uuid)
        return jsonify({"status": "received_invalid_forge_url_data"}), 200


    # 4. Forward Request to Forge Web Trigger
    headers = request.headers.copy()
    headers['X-AgentSphere-Proxy-Secret'] = PROXY_TO_FORGE_SECRET # Copy headers from the original request{

    try:
        # Use lazy formatting
        logger.info("Forwarding event for UUID %s to configured Forge URL...",
                    installation_uuid)
        response = requests.post(forge_url, headers=headers, data=payload, timeout=15) # Increased timeout slightly
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        # Use lazy formatting (%s is fine for status code, or %d)
        logger.info("Successfully forwarded event for UUID %s. Forge response status: %s",
                    installation_uuid, response.status_code)
    except requests.exceptions.Timeout:
        # Use lazy formatting
        logger.error("Timeout error forwarding event for UUID %s to Forge URL.",
                     installation_uuid)
        # Still return 200 to Stripe, but log the failure to reach Forge
        return jsonify({"status": "received_forwarding_timeout"}), 200
    except requests.exceptions.RequestException as e:
        # Includes connection errors, HTTP errors (if raise_for_status used), etc.
        status_code = e.response.status_code if e.response is not None else 'N/A'
        # Use lazy formatting
        logger.error("Error forwarding event for UUID %s to Forge URL. Status: %s, Error: %s",
                     installation_uuid, status_code, e, exc_info=True)
        # Still return 200 to Stripe
        return jsonify({"status": "received_forwarding_error"}), 200

    # 5. Return Success to Stripe
    # Use lazy formatting
    logger.info("Webhook processing complete for event, UUID %s. Returning 200 to Stripe.",
                installation_uuid)
    return jsonify({"status": "received_forwarded"}), 200


@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    # Avoid logging every health check unless needed for debugging traffic
    logger.debug("'/health' endpoint called.")
    return jsonify({"status": "healthy"}), 200

# --- Run the App ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9233))
    # Set debug=False for production environments like Cloud Run
    # Cloud Run manages scaling and restarts, Flask's debug mode isn't suitable there.
    use_debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    # Use lazy formatting (%d for port, %s for boolean/string representation)
    logger.info("Starting Flask server on host 0.0.0.0, port %d, debug=%s", port, use_debug)
    # When running locally with `python app.py`, set FLASK_DEBUG=true for auto-reload
    app.run(host='0.0.0.0', port=port, debug=use_debug)
