
# GitHub Webhook Test — Setup and Run Instructions

This guide explains how to run `Server.py` locally, expose it through ngrok, and configure the GitHub repository webhook and shared secret.

## 1. Project location

The project files are located here:

```text
/code/webhook/webhook_test
├── Server.py
├── .env
└── .venv/   (Python virtual environment, if created)
```

Your `.env` file should contain the webhook secret:

```dotenv
GITHUB_WEBHOOK_SECRET=replace_with_your_generated_secret
```

Use the same secret in GitHub's webhook configuration. Do not commit `.env` to GitHub or share the secret.

## 2. Open Terminal and start Flask

Open a Terminal window and run:

```bash
cd /[FILE_PATH]/webhook/webhook.test
```

Activate the project's virtual environment:

```bash
source .venv/bin/activate
```

If `.venv` does not exist yet, create it first:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required packages in that environment:

```bash
python -m pip install flask python-dotenv
```

Start the server:

```bash
python Server.py
```

The server should listen at:

```text
http://127.0.0.1:5050
```

Keep this Terminal window open while testing. To stop Flask, press `Ctrl+C`.

## 3. Start the ngrok tunnel

Open a **second Terminal window**. Run:

```bash
ngrok http 5050
```

ngrok will display a public HTTPS forwarding URL similar to:

```text
https://example.ngrok-free.app
```

Copy the actual HTTPS URL shown by ngrok. Keep ngrok running while testing. If the URL changes after restarting ngrok, update the GitHub webhook Payload URL.

## 4. Configure the webhook in GitHub

1. Open the target GitHub repository.
2. Go to **Settings → Webhooks**.
3. Click **Add webhook**, or edit the existing webhook.
4. Set **Payload URL** to your current ngrok HTTPS URL followed by `/webhook`, for example:

   ```text
   https://example.ngrok-free.app/webhook
   ```

5. Set **Content type** to `application/json`.
6. Set **Secret** to the exact same value stored as `GITHUB_WEBHOOK_SECRET` in `.env`.
7. Keep **Enable SSL verification** enabled.
8. Under event selection, choose **Just the push event** for a basic test, or select the events your server handles.
9. Ensure the webhook is active, then click **Add webhook** or **Update webhook**.

**Important:** The GitHub webhook Secret field is configured under the repository's **Settings → Webhooks**. It is not a GitHub Actions repository secret.

## 5. Test the webhook

1. Make sure Flask is running in Terminal window 1.
2. Make sure ngrok is running in Terminal window 2.
3. In GitHub, go to **Settings → Webhooks → your webhook → Recent Deliveries**.
4. Open a delivery and inspect its response. You can use **Redeliver** to test it again.
5. For a push event, make a commit and push it to the repository.

A successful delivery should receive HTTP `200`. Your Flask Terminal should show the event type and delivery ID.

## 6. Troubleshooting

- **HTTP 403:** The signature was rejected. Confirm that GitHub's webhook Secret matches `.env` exactly, that the correct `.env` file is loaded, and that Flask was restarted after changing the secret.
- **HTTP 404:** Check that the Payload URL ends with `/webhook` and matches the route in `Server.py`.
- **Connection error / tunnel unavailable:** Ensure both Flask and ngrok are running and ngrok forwards to port `5050`.
- **`ModuleNotFoundError: dotenv`:** Activate `.venv`, then run `python -m pip install python-dotenv`.
- **Wrong ngrok URL:** Use the current HTTPS URL displayed by ngrok and update GitHub's Payload URL.

## 8. Security reminders

- Keep `.env` private and add `.env` to `.gitignore`.
- Never paste the webhook secret into chat, screenshots, or logs.
- Keep SSL verification enabled.
- Verify the `X-Hub-Signature-256` HMAC against the raw request body before processing events.
- Do not execute arbitrary shell commands from webhook payloads.

