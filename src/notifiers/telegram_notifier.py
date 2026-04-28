import os
import requests
import logging

class TelegramNotifier:
    """
    Class to send notifications via Telegram.
    """
    def __init__(self):
        """
        Initializes the TelegramNotifier with credentials from environment variables.
        """
        self.token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.base_url = f"https://api.telegram.org/bot{self.token}/sendMessage"

    def send_message(self, text):
        """
        Sends a message to the configured Telegram chat.

        :param text: The text of the message to send.
        :return: True if the message was sent successfully, False otherwise.
        """
        if not self.token or not self.chat_id:
            logging.warning("Telegram credentials not found. Skipping notification.")
            return False

        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }

        try:
            response = requests.post(self.base_url, json=payload)
            response.raise_for_status()
            logging.info("Telegram notification sent successfully.")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Error sending Telegram notification: {e}")
            return False
