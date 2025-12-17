import feedparser
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RSSCollector:
    """
    Collects news from various RSS feeds.
    """
    def __init__(self, feeds):
        """
        Initializes the RSSCollector with a list of RSS feeds.
        Args:
            feeds (dict): A dictionary of RSS feed names and their URLs.
        """
        self.feeds = feeds

    def fetch_news(self, limit=5):
        """
        Fetches the latest news items from the RSS feeds.
        Args:
            limit (int): The maximum number of news items to fetch from each feed.
        Returns:
            dict: A dictionary of news items, with feed names as keys.
        """
        all_news = {}
        for name, url in self.feeds.items():
            try:
                logging.info(f"Fetching news from {name}...")
                feed = feedparser.parse(url)
                news_items = []
                for entry in feed.entries[:limit]:
                    news_items.append({
                        'title': entry.title,
                        'link': entry.link
                    })
                all_news[name] = news_items
            except Exception as e:
                logging.error(f"Error fetching news from {name}: {e}")
        return all_news

    def save_news(self, news, directory='data'):
        """
        Saves the news to a JSON file.
        Args:
            news (dict): A dictionary of news items.
            directory (str): The directory to save the file in.
        """
        date_str = datetime.now().strftime('%Y%m%d')
        filename = f"{directory}/news_{date_str}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(news, f, indent=4)
            logging.info(f"News saved to {filename}")
        except IOError as e:
            logging.error(f"Error saving news to {filename}: {e}")

if __name__ == '__main__':
    # Example usage
    feeds = {
        "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
    }
    collector = RSSCollector(feeds)
    news = collector.fetch_news(limit=5)
    if news:
        collector.save_news(news)
