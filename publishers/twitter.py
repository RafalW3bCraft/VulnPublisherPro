"""
Twitter/X publisher for VulnPublisherPro
API Documentation: https://developer.twitter.com/en/docs/twitter-api
"""

import logging
from typing import Dict, Any
from .base import BasePublisher
import tweepy
import asyncio

logger = logging.getLogger(__name__)

class TwitterPublisher(BasePublisher):
    """Publisher for Twitter/X platform"""
    
    def __init__(self, config):
        super().__init__(config, 'twitter')
        
        # Twitter API credentials
        self.api_key = self.platform_config.get('api_key')
        self.api_secret = self.platform_config.get('api_secret')
        self.access_token = self.platform_config.get('access_token')
        self.access_token_secret = self.platform_config.get('access_token_secret')
        
        # Initialize Twitter API client
        self.client = None
        if self.validate_config():
            try:
                self.client = tweepy.Client(
                    consumer_key=self.api_key,
                    consumer_secret=self.api_secret,
                    access_token=self.access_token,
                    access_token_secret=self.access_token_secret,
                    wait_on_rate_limit=True
                )
            except Exception as e:
                logger.error(f"Failed to initialize Twitter client: {e}")
    
    def validate_config(self) -> bool:
        """Validate Twitter configuration"""
        required_fields = ['api_key', 'api_secret', 'access_token', 'access_token_secret']
        
        for field in required_fields:
            if not self.platform_config.get(field):
                logger.error(f"Twitter {field} not configured")
                return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Twitter"""
        if not self.client:
            return self.create_error_response("Twitter client not initialized")
        
        try:
            # Handle different content types
            content_type = content.get('content_type', 'summary')
            
            if content_type == 'thread':
                return await self._publish_thread(content, vulnerability)
            else:
                return await self._publish_single_tweet(content, vulnerability)
                
        except Exception as e:
            logger.error(f"Error publishing to Twitter: {e}")
            return self.create_error_response(str(e))
    
    async def _publish_single_tweet(self, content: Dict[str, Any], 
                                   vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish a single tweet"""
        try:
            # Format content for Twitter
            tweet_text = self.format_content_for_platform(content)
            
            # Add hashtags if not present
            hashtags = content.get('hashtags', ['#cybersecurity', '#infosec', '#vulnerability'])
            tweet_text = self.add_platform_hashtags(tweet_text, hashtags)
            
            # Ensure tweet is within character limit
            tweet_text = self.truncate_content(tweet_text, 280)
            
            # Post tweet (run in thread pool to avoid blocking)
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                lambda: self.client.create_tweet(text=tweet_text)
            )
            
            if response.data:
                tweet_id = response.data['id']
                tweet_url = f"https://twitter.com/user/status/{tweet_id}"
                
                logger.info(f"Successfully posted tweet: {tweet_id}")
                
                return self.create_success_response(
                    post_data={'text': tweet_text, 'response': response.data},
                    post_id=str(tweet_id),
                    post_url=tweet_url
                )
            else:
                return self.create_error_response("No tweet data returned", response)
                
        except Exception as e:
            logger.error(f"Error posting single tweet: {e}")
            return self.create_error_response(str(e))
    
    async def _publish_thread(self, content: Dict[str, Any], 
                             vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish a Twitter thread"""
        try:
            tweets = content.get('tweets', [])
            if not tweets:
                return self.create_error_response("No tweets in thread content")
            
            thread_ids = []
            reply_to_id = None
            
            loop = asyncio.get_event_loop()
            
            for i, tweet_text in enumerate(tweets):
                # Ensure each tweet is within character limit
                tweet_text = self.truncate_content(tweet_text, 280)
                
                try:
                    if reply_to_id:
                        # Reply to previous tweet
                        response = await loop.run_in_executor(
                            None,
                            lambda: self.client.create_tweet(
                                text=tweet_text,
                                in_reply_to_tweet_id=reply_to_id
                            )
                        )
                    else:
                        # First tweet in thread
                        response = await loop.run_in_executor(
                            None,
                            lambda: self.client.create_tweet(text=tweet_text)
                        )
                    
                    if response.data:
                        tweet_id = response.data['id']
                        thread_ids.append(str(tweet_id))
                        reply_to_id = tweet_id
                        
                        logger.info(f"Posted thread tweet {i+1}/{len(tweets)}: {tweet_id}")
                        
                        # Rate limiting between thread tweets
                        if i < len(tweets) - 1:  # Don't sleep after last tweet
                            await asyncio.sleep(1)
                    else:
                        logger.error(f"Failed to post thread tweet {i+1}: {response}")
                        break
                        
                except Exception as e:
                    logger.error(f"Error posting thread tweet {i+1}: {e}")
                    break
            
            if thread_ids:
                first_tweet_url = f"https://twitter.com/user/status/{thread_ids[0]}"
                
                return self.create_success_response(
                    post_data={
                        'thread_ids': thread_ids,
                        'total_tweets': len(thread_ids),
                        'tweets': tweets[:len(thread_ids)]
                    },
                    post_id=thread_ids[0],
                    post_url=first_tweet_url
                )
            else:
                return self.create_error_response("Failed to post any tweets in thread")
                
        except Exception as e:
            logger.error(f"Error posting Twitter thread: {e}")
            return self.create_error_response(str(e))
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Twitter"""
        if content.get('content_type') == 'alert':
            # Format alert content
            alert_text = content.get('content', '')
            return alert_text
        else:
            # Use platform variant if available
            platform_variants = content.get('platform_variants', {})
            if 'twitter' in platform_variants:
                return platform_variants['twitter']
            
            # Use main content
            return content.get('content', '')
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Twitter API connection"""
        if not self.client:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Twitter client not initialized'
            }
        
        try:
            loop = asyncio.get_event_loop()
            user = await loop.run_in_executor(None, lambda: self.client.get_me())
            
            if user.data:
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as @{user.data.username}',
                    'user_data': {
                        'username': user.data.username,
                        'name': user.data.name,
                        'id': user.data.id
                    }
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get user data'
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get Twitter analytics for a tweet"""
        if not self.client:
            return self.create_error_response("Twitter client not initialized")
        
        try:
            loop = asyncio.get_event_loop()
            tweet = await loop.run_in_executor(
                None,
                lambda: self.client.get_tweet(
                    post_id, 
                    tweet_fields=['public_metrics', 'created_at']
                )
            )
            
            if tweet.data:
                metrics = tweet.data.public_metrics or {}
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'post_id': post_id,
                    'analytics': {
                        'retweets': metrics.get('retweet_count', 0),
                        'likes': metrics.get('like_count', 0),
                        'replies': metrics.get('reply_count', 0),
                        'quotes': metrics.get('quote_count', 0),
                        'impressions': metrics.get('impression_count', 0),
                        'created_at': str(tweet.data.created_at) if tweet.data.created_at else None
                    }
                }
            else:
                return self.create_error_response("Tweet not found", post_id)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
    
    async def delete_post(self, post_id: str) -> Dict[str, Any]:
        """Delete a tweet"""
        if not self.client:
            return self.create_error_response("Twitter client not initialized")
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.client.delete_tweet(post_id)
            )
            
            if result.data and result.data.get('deleted'):
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'post_id': post_id,
                    'message': 'Tweet deleted successfully'
                }
            else:
                return self.create_error_response("Failed to delete tweet", result)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
