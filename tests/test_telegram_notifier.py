import unittest
from unittest.mock import patch, MagicMock
import os
from src.notifiers.telegram_notifier import TelegramNotifier

class TestTelegramNotifier(unittest.TestCase):

    @patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "fake_token", "TELEGRAM_CHAT_ID": "fake_chat_id"})
    def test_send_message_success(self):
        notifier = TelegramNotifier()

        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response

            result = notifier.send_message("Test message")

            self.assertTrue(result)
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            self.assertEqual(kwargs['json']['text'], "Test message")
            self.assertEqual(kwargs['json']['chat_id'], "fake_chat_id")

    @patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""})
    def test_send_message_no_credentials(self):
        # We need to ensure the environment variables are truly empty/none for this test
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}):
            notifier = TelegramNotifier()
            result = notifier.send_message("Test message")
            self.assertFalse(result)

    @patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "fake_token", "TELEGRAM_CHAT_ID": "fake_chat_id"})
    def test_send_message_failure(self):
        notifier = TelegramNotifier()

        with patch('requests.post') as mock_post:
            import requests
            mock_post.side_effect = requests.exceptions.RequestException("API Error")

            result = notifier.send_message("Test message")

            self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
